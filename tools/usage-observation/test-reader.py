"""Offline protocol test. No SSH, listening sockets or production credentials."""
import contextlib
import hashlib
import hmac
import io
import json
import pathlib
import unittest
from unittest.mock import patch


class ReaderTests(unittest.TestCase):
    def run_reader(self, response):
        settings = dict(key='01'*32, campaign='a'*32, relay='fixture', seconds=5, interval_ms=5000)
        source = pathlib.Path(__file__).with_name('relay-reader.py').read_text()
        source = source.replace('__SETTINGS__', json.dumps(settings))
        output = io.StringIO()
        clock = [0]

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *unused):
                pass

            def read(self, size):
                return json.dumps(response).encode()

        def sleep(seconds):
            clock[0] += seconds

        with patch('pathlib.Path.read_text', return_value='RELAY_STATS_TOKEN=fixture-secret'), \
                patch('urllib.request.urlopen', return_value=Response()), \
                patch('time.monotonic', side_effect=lambda: clock[0]), \
                patch('time.sleep', side_effect=sleep), \
                contextlib.redirect_stdout(output):
            exec(compile(source, 'reader-fixture', 'exec'), {})
        return json.loads(output.getvalue())

    def test_export_does_not_contain_account_destinations_or_credentials(self):
        response = dict(schema=1, mode='measurement_only', run_id='b'*32, unix_ms=1700000000000,
                        busy_accounts=0, account_count=1, truncated=False,
                        return_sessions=[dict(account='fixture-owner', session='fixture-session', created_at=10,
                                              sample_mono_ms=5, frame_bytes_out=1000, packets_out=10,
                                              destination='must-not-leave-the-relay')],
                        busy_return_sessions=0, return_sessions_truncated=False,
                        accounts=[dict(account='fixture-owner', epoch=1, sample_mono_ms=5,
                                       offered=[1, 100, 2, 200], new_flows=1, budget_dropped_packets=0,
                                       destination='must-not-leave-the-relay')])
        row = self.run_reader(response)
        self.assertTrue(row['valid'])
        expected = hmac.new(bytes.fromhex('01'*32), b'account\0fixture-owner', hashlib.sha256).hexdigest()
        self.assertEqual(row['accounts'][0]['account'], expected)
        text = json.dumps(row)
        self.assertEqual(len(row['return_sessions'][0]['session']), 64)
        for private in ['fixture-owner', 'fixture-secret', 'fixture-session', 'destination', 'must-not-leave-the-relay']:
            self.assertNotIn(private, text)

    def test_old_endpoint_is_unknown_not_zero_usage(self):
        row = self.run_reader(dict(error='not_found'))
        self.assertFalse(row['valid'])
        self.assertEqual(row['error'], 'ValueError')
        self.assertNotIn('accounts', row)


if __name__ == '__main__':
    unittest.main()
