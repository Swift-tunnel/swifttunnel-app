import type { AppSettings, ServerInfo, ServerRegion } from "../../lib/types";

export function RelayPicker({ region, servers, latencies, value, disabled, onChange }: {
  region: ServerRegion;
  servers: ServerInfo[];
  latencies: Map<string, number | null>;
  value: AppSettings["manual_relay"];
  disabled: boolean;
  onChange: (relay: AppSettings["manual_relay"]) => void;
}) {
  const choices = servers.filter(s => region.servers.includes(s.region));
  const current = choices.find(s => s.region === value?.server_id && s.ip === value.ip &&
    (s.relay_port ?? 51821) === value.port && s.relay_available);
  const unavailable = value !== null && (value.region !== region.id || !current);
  return (
    <div className="mb-3 rounded-[var(--radius-card)] surface-card p-4">
      <label htmlFor="manual-relay" className="mb-2 block text-[13px] font-semibold text-text-primary">
        {region.name} relay
      </label>
      <select id="manual-relay" disabled={disabled}
        className="w-full rounded-lg border border-border-subtle bg-bg-card px-3 py-2 text-[13px] text-text-primary disabled:opacity-50"
        value={unavailable ? "unavailable" : value?.server_id ?? ""}
        onChange={event => {
          const server = choices.find(s => s.region === event.target.value && s.relay_available);
          onChange(server ? { region: region.id, server_id: server.region, ip: server.ip,
            port: server.relay_port ?? 51821 } : null);
        }}>
        <option value="">Automatic (recommended)</option>
        {unavailable && <option value="unavailable" disabled>{value?.server_id} (unavailable or changed)</option>}
        {choices.map(server => {
          const ms = latencies.get(`relay:${server.region}`);
          return <option key={server.region} value={server.region} disabled={!server.relay_available}>
            {server.region} · {!server.relay_available ? "Unavailable" : ms == null ? "Ping unavailable" : `${ms} ms`}
          </option>;
        })}
      </select>
      <p className="mt-2 text-[11px] text-text-muted">
        {unavailable ? "Choose another relay or Automatic before connecting." :
          "Ping is measured to the relay. A manual choice stays fixed until you disconnect."}
      </p>
    </div>
  );
}
