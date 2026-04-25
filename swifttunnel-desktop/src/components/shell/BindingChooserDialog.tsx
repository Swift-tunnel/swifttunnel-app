import { useVpnStore } from "../../stores/vpnStore";
import { Dialog } from "../ui/Dialog";
import { Chip } from "../ui/Chip";
import type { BindingCandidateInfo } from "../../lib/types";

export function BindingChooserDialog() {
  const bindingPreflight = useVpnStore((s) => s.bindingPreflight);
  const resumeConnectWithAdapter = useVpnStore((s) => s.resumeConnectWithAdapter);
  const dismissBindingChooser = useVpnStore((s) => s.dismissBindingChooser);

  if (!bindingPreflight) return null;

  return (
    <Dialog
      open
      onClose={dismissBindingChooser}
      title="Choose network adapter"
      description="SwiftTunnel needs a one-time split-tunnel choice for this network."
      maxWidth={520}
    >
      <div
        className="mb-3 rounded-[5px] px-3 py-2 text-[11.5px]"
        style={{
          backgroundColor: "var(--color-bg-base)",
          border: "1px solid var(--color-border-subtle)",
          color: "var(--color-text-secondary)",
        }}
      >
        <div>{bindingPreflight.reason}</div>
        <div className="mt-1 text-[10.5px] text-text-dimmed">
          Route source: {bindingPreflight.route_resolution_source}
          {bindingPreflight.route_resolution_target_ip
            ? ` (${bindingPreflight.route_resolution_target_ip})`
            : ""}
          {" · "}
          ifIndex: {bindingPreflight.resolved_if_index ?? "n/a"}
        </div>
      </div>

      <div className="flex flex-col gap-2">
        {bindingPreflight.candidates.map((candidate) => (
          <CandidateRow
            key={
              candidate.guid ||
              `${candidate.friendly_name}-${candidate.if_index ?? "na"}`
            }
            candidate={candidate}
            recommended={candidate.guid === bindingPreflight.recommended_guid}
            onChoose={(guid) => void resumeConnectWithAdapter(guid)}
          />
        ))}
      </div>
    </Dialog>
  );
}

function CandidateRow({
  candidate,
  recommended,
  onChoose,
}: {
  candidate: BindingCandidateInfo;
  recommended: boolean;
  onChoose: (guid: string) => void;
}) {
  const label =
    candidate.friendly_name || candidate.description || candidate.guid;
  return (
    <button
      type="button"
      onClick={() => onChoose(candidate.guid)}
      className="group flex items-center justify-between gap-3 rounded-[var(--radius-card)] px-3.5 py-3 text-left transition-colors"
      style={{
        backgroundColor: "var(--color-bg-base)",
        border: `1px solid ${recommended ? "var(--color-accent-primary)" : "var(--color-border-subtle)"}`,
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = "var(--color-bg-hover)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = "var(--color-bg-base)";
      }}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="truncate text-[13px] font-medium text-text-primary">
            {label}
          </span>
          {recommended && <Chip tone="accent" uppercase>Recommended</Chip>}
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[10.5px]">
          <span className="text-text-muted">{candidate.kind}</span>
          <span className="text-text-dimmed">·</span>
          <span
            style={{
              color: candidate.is_up
                ? "var(--color-status-connected)"
                : "var(--color-text-dimmed)",
            }}
          >
            {candidate.is_up ? "up" : "down"}
          </span>
          {candidate.is_default_route && (
            <>
              <span className="text-text-dimmed">·</span>
              <span className="text-text-muted">default route</span>
            </>
          )}
        </div>
        <div className="mt-1 font-mono text-[10px] text-text-dimmed">
          {candidate.stage.replace(/_/g, " ")} · {candidate.reason}
        </div>
      </div>
      <span className="shrink-0 text-[11px] font-semibold text-accent-secondary">
        Use →
      </span>
    </button>
  );
}
