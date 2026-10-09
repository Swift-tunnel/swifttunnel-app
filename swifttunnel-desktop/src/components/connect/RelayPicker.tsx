import type { AppSettings, ServerInfo, ServerRegion, GameRouteStatus } from "../../lib/types";
import { relayGameEstimate } from "../../lib/gamePing";

export function RelayPicker({ region, servers, latencies, value, disabled, onChange, gameRoute, compareGamePaths = true }: {
  region: ServerRegion;
  gameRoute?: GameRouteStatus | null;
  compareGamePaths?: boolean;
  servers: ServerInfo[];
  latencies: Map<string, number | null>;
  value: AppSettings["manual_relay"];
  disabled: boolean;
  onChange: (relay: AppSettings["manual_relay"]) => void;
}) {
  const matches = (server: ServerInfo) => value?.region === region.id &&
    server.region === value.server_id && server.ip === value.ip &&
    (server.relay_port ?? 51821) === value.port;
  const choices = region.servers.map(id => ({ id, server: servers.find(s => s.region === id) }));
  const unavailable = value !== null && !choices.some(({ server }) => server?.relay_available && matches(server));
  return (
    <div className="pb-3 pl-[58px] pr-3.5" role="group" aria-label={`${region.name} relays`}>
      <div className="w-full max-w-[460px] overflow-hidden rounded-[8px] border border-border-subtle bg-bg-elevated">
        <RelayOption label="Auto" detail={compareGamePaths ? "Compare game paths at join" : "Lowest relay ping in region"} active={value === null}
          disabled={disabled} onClick={() => onChange(null)} />
        {choices.map(({ id, server }) => {
          const ms = latencies.get(`relay:${id}`);
          const estimate = relayGameEstimate(gameRoute, server);
          return <RelayOption key={id} label={id}
            detail={!server?.relay_available ? "Unavailable" : estimate ? `~${estimate.estimated_game_ms} ms game Â· ${estimate.relay_ms} ms relay` : ms == null ? "Relay ping unavailable" : `${ms} ms relay`}
            active={!!server && matches(server)} disabled={disabled || !server?.relay_available}
            onClick={() => { if (server?.relay_available) onChange({ region: region.id,
              server_id: id, ip: server.ip, port: server.relay_port ?? 51821 }); }} />;
        })}
      </div>
      <p className="mt-2 text-[11px] text-text-muted">
        {gameRoute?.relay_estimates?.length
          ? `Estimated game ping to ${gameRoute.game_location}: relay ping + relay-to-game network ping. Not Robloxâ€™s own reading.`
          : "Relay ping only. Game estimates appear when connected and a game path is measured."}
      </p>
      {unavailable && <p className="mt-2 text-[11px] text-text-muted">
        Your saved relay is unavailable or changed. Choose another relay or Auto.
      </p>}
    </div>
  );
}

function RelayOption({ label, detail, active, disabled, onClick }: {
  label: string; detail: string; active: boolean; disabled: boolean; onClick: () => void;
}) {
  return <button type="button" disabled={disabled} aria-pressed={active} onClick={onClick}
    className={`flex min-h-8 w-full items-center gap-2 px-2.5 py-1 text-left text-[11.5px] transition-colors hover:bg-bg-hover disabled:cursor-not-allowed disabled:opacity-50 ${active ? "bg-bg-hover text-text-primary" : "text-text-secondary"}`}>
    <span aria-hidden="true" className="w-4 shrink-0 text-center">{active ? "✓" : ""}</span>
    <span className="min-w-0 truncate font-mono font-medium">{label}</span>
    <span className="ml-auto shrink-0 text-[10px] text-text-muted">{detail}</span>
  </button>;
}
