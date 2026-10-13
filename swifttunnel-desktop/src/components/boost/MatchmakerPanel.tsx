import { useEffect, useState } from "react";
import {
  Button,
  Dialog,
  ErrorBanner,
  Field,
  Panel,
  Row,
  Select,
  Toggle,
  Watermark,
  fieldClass,
} from "../ui";
import {
  gamesDatacenters,
  gamesLauncherConfig,
  gamesSaveLauncherConfig,
  systemOpenUrl,
} from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import { useSettingsStore } from "../../stores/settingsStore";
import type {
  LauncherConfig,
  NamedGameProfile,
  RobloxDatacenter,
} from "../../lib/types";
import { Notice } from "./Notice";

export function MatchmakerPanel() {
  const [config, setConfig] = useState<LauncherConfig | null>(null);
  const [centers, setCenters] = useState<RobloxDatacenter[]>([]);
  const [query, setQuery] = useState("");
  const [skipped, setSkipped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [profileName, setProfileName] = useState("");
  const [importing, setImporting] = useState(false);
  const [raw, setRaw] = useState("");
  useEffect(() => {
    let alive = true;
    void gamesLauncherConfig()
      .then((c) => {
        if (alive) {
          setConfig(c);
          setSkipped(c.matchmaker.skipped_games.join(", "));
        }
      })
      .catch((e) => {
        if (alive) setError(formatErrorMessage(e));
      });
    void gamesDatacenters()
      .then((c) => {
        if (alive) setCenters(c);
      })
      .catch((e) => {
        if (alive) setError(formatErrorMessage(e));
      });
    return () => {
      alive = false;
    };
  }, []);
  async function save(
    next: LauncherConfig,
    message = "Launcher preferences saved.",
  ) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await gamesSaveLauncherConfig(next);
      setConfig(next);
      setNotice(message);
      return true;
    } catch (e) {
      setError(formatErrorMessage(e));
      return false;
    } finally {
      setBusy(false);
    }
  }
  const patch = (change: Partial<LauncherConfig["matchmaker"]>) =>
    setConfig((c) =>
      c ? { ...c, matchmaker: { ...c.matchmaker, ...change } } : c,
    );
  async function saveProfiles(profiles: NamedGameProfile[], message: string) {
    if (!config) return false;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const persisted = await gamesLauncherConfig();
      await gamesSaveLauncherConfig({ ...persisted, profiles });
      setConfig({ ...config, profiles });
      setNotice(message);
      return true;
    } catch (e) {
      setError(formatErrorMessage(e));
      return false;
    } finally {
      setBusy(false);
    }
  }
  async function addProfile() {
    if (!config) return;
    const settings = {
      ...useSettingsStore.getState().settings.config.roblox_settings,
    };
    if (
      await saveProfiles(
        [...config.profiles, { name: profileName.trim(), settings }],
        "Current Roblox settings saved as a named profile.",
      )
    )
      setProfileName("");
  }
  async function importProfile() {
    if (!config) return;
    try {
      if (raw.length > 16384) throw new Error("Keep the profile under 16 KB.");
      const profile = JSON.parse(raw) as NamedGameProfile;
      if (!profile || typeof profile.name !== "string" || !profile.settings)
        throw new Error(
          "Paste an exported SwiftTunnel profile with a name and settings.",
        );
      if (
        await saveProfiles(
          [...config.profiles, profile],
          "Profile imported. Select it in a game's settings to use it.",
        )
      ) {
        setImporting(false);
        setRaw("");
      }
    } catch (e) {
      setError(formatErrorMessage(e));
    }
  }
  if (!config)
    return (
      <>
        {error ? (
          <ErrorBanner tone="error">{error}</ErrorBanner>
        ) : (
          <Notice busy>Loading launcher preferences...</Notice>
        )}
      </>
    );
  const m = config.matchmaker;
  return (
    <div className="flex flex-col gap-4" data-search-anchor="matchmaker">
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {notice && <Notice>{notice}</Notice>}
      <section className="instrument relative isolate overflow-hidden px-4 py-3.5">
        <Watermark
          icon="globe"
          at="right"
          size={120}
          rotate={-14}
          opacity={0.05}
        />
        <p className="eyebrow">Matchmaker</p>
        <p className="mt-2 text-[12px] text-text-muted">
          Pick a public server when you press Play here. Roblox handles its own
          updates. Running games stay where they are.
        </p>
      </section>
      <Panel eyebrow="Choose your next server" flush>
        <div className="divide-y divide-border-subtle">
          <Row
            label="Enable Matchmaker"
            desc="Search allowed datacenters before launching from SwiftTunnel."
          >
            <Toggle
              enabled={m.enabled}
              disabled={busy}
              ariaLabel="Enable Matchmaker"
              onChange={(enabled) => patch({ enabled })}
            />
          </Row>
          <Row
            label="Offer a better datacenter after joining"
            desc="One optional check per join. A prompt expires after 20 seconds and keeps you in your current game."
          >
            <Toggle
              enabled={m.offer_better_server}
              disabled={busy}
              ariaLabel="Offer a better server"
              onChange={(offer_better_server) => patch({ offer_better_server })}
            />
          </Row>
          <Row
            label="Prepare a matching SwiftTunnel relay"
            desc="Connects before Play. Connections started for the game stop when it ends."
          >
            <Toggle
              enabled={m.prepare_tunnel}
              disabled={busy}
              ariaLabel="Matchmaker prepares tunnel"
              onChange={(prepare_tunnel) => patch({ prepare_tunnel })}
            />
          </Row>
          <Row
            label="What to join"
            desc="Closest uses measured network paths. Fewer players compares the servers found within your search limit."
          >
            <Select
              aria-label="Matchmaker mode"
              value={m.mode}
              disabled={busy}
              onChange={(e) => patch({ mode: e.target.value as typeof m.mode })}
            >
              <option value="closest">Closest measured path</option>
              <option value="fewer_players">Fewer players</option>
            </Select>
          </Row>
          <Row
            label="Preferred datacenter"
            desc="Search this location first. Leave blank to use measured paths."
          >
            <Select
              aria-label="Matchmaker preferred datacenter"
              value={m.preferred_datacenter ?? ""}
              disabled={busy}
              onChange={(e) =>
                patch({
                  preferred_datacenter: e.target.value
                    ? Number(e.target.value)
                    : null,
                })
              }
            >
              <option value="">Automatic</option>
              {centers
                .filter((c) => !m.blocked_datacenters.includes(c.id))
                .map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.city}, {c.country}
                  </option>
                ))}
            </Select>
          </Row>
          <Row
            label="Minimum free slots"
            desc="Only use public servers with confirmed room for this many players."
          >
            <input
              aria-label="Minimum free slots"
              type="number"
              min={1}
              max={20}
              className={`${fieldClass} w-24`}
              value={m.minimum_free_slots}
              onChange={(e) =>
                patch({ minimum_free_slots: Number(e.target.value) })
              }
            />
          </Row>
          <Row
            label="Search limit"
            desc="Checks a bounded set of servers, with a 20-second server-search deadline."
          >
            <input
              aria-label="Search limit"
              type="number"
              min={10}
              max={200}
              className={`${fieldClass} w-24`}
              value={m.search_limit}
              onChange={(e) => patch({ search_limit: Number(e.target.value) })}
            />
          </Row>
        </div>
      </Panel>
      <Panel
        eyebrow="Allowed datacenters"
        desc={`${centers.length - m.blocked_datacenters.filter((id) => centers.some((c) => c.id === id)).length} locations allowed. A game's explicit region choice takes priority.`}
      >
        <div className="flex gap-2">
          <input
            aria-label="Find datacenter"
            placeholder="Search city or country"
            className={`${fieldClass} flex-1`}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            onClick={() => patch({ blocked_datacenters: [] })}
          >
            Allow all
          </Button>
        </div>
        <div className="mt-3 max-h-[270px] overflow-y-auto divide-y divide-border-subtle">
          {centers
            .filter((c) =>
              `${c.city} ${c.country}`
                .toLowerCase()
                .includes(query.toLowerCase()),
            )
            .map((c) => (
              <Row key={c.id} label={c.city} desc={c.country}>
                <Toggle
                  enabled={!m.blocked_datacenters.includes(c.id)}
                  disabled={busy}
                  ariaLabel={`Allow ${c.city}`}
                  onChange={(allowed) =>
                    patch({
                      blocked_datacenters: allowed
                        ? m.blocked_datacenters.filter((id) => id !== c.id)
                        : [...m.blocked_datacenters, c.id],
                      preferred_datacenter:
                        !allowed && m.preferred_datacenter === c.id
                          ? null
                          : m.preferred_datacenter,
                    })
                  }
                />
              </Row>
            ))}
        </div>
      </Panel>
      <Panel eyebrow="Exceptions & recovery">
        <Field
          label="Skipped games"
          hint="Comma-separated place IDs. These games use normal Roblox matchmaking."
        >
          <input
            value={skipped}
            onChange={(e) => setSkipped(e.target.value)}
            placeholder="1818, 10449761463"
            className={fieldClass}
          />
        </Field>
        <Row
          label="Offer rejoin after an unexpected exit"
          desc="Shows a review prompt. It never relaunches automatically or loops."
        >
          <Toggle
            enabled={config.offer_recovery}
            disabled={busy}
            ariaLabel="Offer crash recovery"
            onChange={(offer_recovery) =>
              setConfig({ ...config, offer_recovery })
            }
          />
        </Row>
        <div className="mt-3 flex justify-end">
          <Button
            size="sm"
            loading={busy}
            onClick={() =>
              void save({
                ...config,
                matchmaker: {
                  ...m,
                  skipped_games: [
                    ...new Set(skipped.split(/[\s,]+/).filter(Boolean)),
                  ],
                },
              })
            }
          >
            Save Matchmaker
          </Button>
        </div>
      </Panel>
      <Panel
        eyebrow="Named profiles"
        desc="Save your current FPS, graphics and FastFlags, then assign a profile to any game. Other launchers' settings and login are kept."
      >
        <div className="flex gap-2">
          <input
            aria-label="Profile name"
            placeholder="Profile name"
            maxLength={48}
            className={`${fieldClass} flex-1`}
            value={profileName}
            onChange={(e) => setProfileName(e.target.value)}
          />
          <Button
            size="sm"
            disabled={busy || !profileName.trim()}
            onClick={() => void addProfile()}
          >
            Save current
          </Button>
          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            onClick={() => setImporting(true)}
          >
            Import
          </Button>
        </div>
        <div className="mt-3 divide-y divide-border-subtle">
          {config.profiles.map((p) => (
            <Row
              key={p.name}
              label={p.name}
              desc={`${p.settings.unlock_fps ? p.settings.target_fps : 60} FPS · ${p.settings.graphics_quality} · ${p.settings.custom_fflags_enabled ? "Custom flags" : p.settings.ultraboost ? "Ultraboost" : "Default flags"}`}
            >
              <Button
                size="sm"
                variant="ghost"
                onClick={() =>
                  void navigator.clipboard
                    .writeText(JSON.stringify(p, null, 2))
                    .then(
                      () => setNotice("Profile JSON copied."),
                      (e) => setError(formatErrorMessage(e)),
                    )
                }
              >
                Export
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() =>
                  void saveProfiles(
                    config.profiles.filter((old) => old.name !== p.name),
                    "Profile removed. Games using it will ask you to choose another.",
                  )
                }
              >
                Remove
              </Button>
            </Row>
          ))}
        </div>
      </Panel>
      <Dialog
        open={importing}
        onClose={() => setImporting(false)}
        title="Import a SwiftTunnel profile"
        description="Review the exported JSON before adding it. Importing does not apply it to Roblox."
      >
        <div className="flex flex-col gap-3">
          <textarea
            aria-label="Profile JSON"
            rows={12}
            maxLength={16384}
            className={`${fieldClass} font-mono text-[11px]`}
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
          />
          {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
          <Button size="sm" loading={busy} onClick={() => void importProfile()}>
            Validate & add
          </Button>
        </div>
      </Dialog>
      <p className="px-1 text-[11px] text-text-muted">
        Public server locations by{" "}
        <button
          type="button"
          className="underline underline-offset-2 hover:text-text-primary"
          onClick={() => void systemOpenUrl("https://www.rovalra.com")}
        >
          RoValra
        </button>
        . Availability by Roblox.
      </p>
    </div>
  );
}
