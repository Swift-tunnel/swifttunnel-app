# Read-only stdin program for an explicitly launched SSH collector. Never
# installed as a service. Only reads the optional localhost research endpoint.
import hashlib, hmac, json, pathlib, time, urllib.request

settings = json.loads('__SETTINGS__')
key = bytes.fromhex(settings['key'])
env = {}
for line in pathlib.Path('/etc/swifttunnel/relay.env').read_text().splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        name, value = line.split('=', 1)
        env[name.strip()] = value.strip().strip('"').strip("'")
token = env.get('RELAY_STATS_TOKEN', '')
deadline = time.monotonic() + settings['seconds']
while time.monotonic() < deadline:
    started = time.monotonic()
    record = dict(schema=1, kind='relay', campaign=settings['campaign'], relay=settings['relay'],
                  interval_ms=settings['interval_ms'], unix_ms=int(time.time()*1000), valid=False)
    try:
        request = urllib.request.Request('http://127.0.0.1:51822/v1/usage-observation',
                                         headers={'Authorization': 'Bearer '+token})
        with urllib.request.urlopen(request, timeout=2) as response:
            raw = response.read(4*1024*1024+1)
        if len(raw) > 4*1024*1024:
            raise ValueError('response_bound')
        data = json.loads(raw)
        if data.get('schema') != 1 or data.get('mode') != 'measurement_only':
            raise ValueError('unsupported_schema')
        rows = []
        for row in data['accounts']:
            # Build an allowlisted record; never pass through arbitrary fields.
            identity = hmac.new(key, ('account\0'+str(row['account']).strip()).encode(), hashlib.sha256).hexdigest()
            rows.append(dict(account=identity, epoch=row['epoch'], sample_mono_ms=row['sample_mono_ms'],
                             offered=row['offered'], new_flows=row['new_flows'],
                             budget_dropped_packets=row['budget_dropped_packets']))
        if len(rows) > 4096:
            raise ValueError('row_bound')
        returns = []
        for row in data['return_sessions']:
            identity = hmac.new(key, ('account\0'+str(row['account']).strip()).encode(), hashlib.sha256).hexdigest()
            session = hmac.new(key, ('session\0'+settings['relay']+'\0'+str(row['session'])+'\0'+str(row['created_at'])).encode(), hashlib.sha256).hexdigest()
            returns.append(dict(account=identity, session=session, created_at=row['created_at'],
                                sample_mono_ms=row['sample_mono_ms'], frame_bytes_out=row['frame_bytes_out'],
                                packets_out=row['packets_out']))
        if len(returns) > 4096:
            raise ValueError('return_bound')
        record.update(valid=True, run_id=data['run_id'], unix_ms=data['unix_ms'], accounts=rows,
                      busy_accounts=data['busy_accounts'], account_count=data['account_count'], truncated=data['truncated'],
                      return_sessions=returns, busy_return_sessions=data['busy_return_sessions'],
                      return_sessions_truncated=data['return_sessions_truncated'])
    except Exception as error:
        # Exception messages can contain URLs or headers; emit only the class.
        record['error'] = type(error).__name__
    record['collection_ms'] = round((time.monotonic()-started)*1000, 3)
    print(json.dumps(record, separators=(',', ':')), flush=True)
    time.sleep(max(0, min(settings['interval_ms']/1000-(time.monotonic()-started), deadline-time.monotonic())))
