import { useEffect, useState } from "react";
import {
  Button,
  Dialog,
  ErrorBanner,
  Icon,
  Panel,
  Row,
  Segmented,
  Select,
  SliderInput,
  Toggle,
  compactFieldClass,
} from "../ui";
import { Flag } from "../ui/Flag";
import {
  gamesDatacenters,
  gamesLauncherConfig,
  gamesSaveLauncherConfig,
  systemOpenUrl,
} from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import { parsePlaceInput } from "../../lib/robloxGames";
import { useGameLibraryStore } from "../../stores/gameLibraryStore";
import { useSettingsStore } from "../../stores/settingsStore";
import type {
  LauncherConfig,
  NamedGameProfile,
  RobloxDatacenter,
} from "../../lib/types";
import { Notice } from "./Notice";

export function MatchmakerPanel() {
  const [config, setConfig] = useState<LauncherConfig | null>(null);
  // What is on disk, so the page can tell when there is something to save.
  const [saved, setSaved] = useState<LauncherConfig | null>(null);
  const [centers, setCenters] = useState<RobloxDatacenter[]>([]);
  const [query, setQuery] = useState("");
  const [skipInput, setSkipInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [profileName, setProfileName] = useState("");
  const [importing, setImporting] = useState(false);
  const [raw, setRaw] = useState("");
  const games = useGameLibraryStore((s) => s.library?.entries);
  useEffect(() => {
    let alive = true;
    void gamesLauncherConfig()
      .then((c) => {
        if (alive) {
          setConfig(c);
          setSaved(c);
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
  async function save(next: LauncherConfig, message = "Matchmaker saved.") {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await gamesSaveLauncherConfig(next);
      setConfig(next);
      setSaved(next);
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
      setSaved((s) => (s ? { ...s, profiles } : s));
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
        "Profile saved. Pick it in a game's settings to use it.",
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
          "Profile imported. Pick it in a game's settings to use it.",
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
          <Notice busy>Loading Matchmaker...</Notice>
        )}
      </>
    );
  const m = config.matchmaker;
  const dirty =
    !!saved &&
    JSON.stringify([m, config.offer_recovery]) !==
      JSON.stringify([saved.matchmaker, saved.offer_recovery]);
  const allowed = centers.filter((c) => !m.blocked_datacenters.includes(c.id));
  const shown = centers.filter((c) =>
    `${c.city} ${c.country}`.toLowerCase().includes(query.toLowerCase()),
  );
  const skipPlace = parsePlaceInput(skipInput);
  function addSkipped() {
    if (!skipPlace) return;
    if (!m.skipped_games.includes(skipPlace))
      patch({ skipped_games: [...m.skipped_games, skipPlace] });
    setSkipInput("");
  }
  return (
    <div className="flex flex-col gap-4" data-search-anchor="matchmaker">
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {notice && <Notice>{notice}</Notice>}
      <Panel
        flush
        watermark={{ icon: "globe", at: "right", size: 124, rotate: -14, opacity: 0.05 }}
      >
        <Row
          label="Matchmaker"
          desc="Picks a public server in your allowed locations when you press Play."
        >
          <Toggle
            enabled={m.enabled}
            disabled={busy}
            ariaLabel="Enable Matchmaker"
            onChange={(enabled) => patch({ enabled })}
          />
        </Row>
      </Panel>
      <Panel eyebrow="How it picks" flush>
        <div className="divide-y divide-border-subtle border-t border-border-subtle">
          <Row
            label="Prefer"
            desc="Closest goes by measured ping. Fewer players takes the emptiest server it finds."
          >
            <Segmented<LauncherConfig["matchmaker"]["mode"]>
              ariaLabel="Matchmaker mode"
              value={m.mode}
              disabled={busy}
              options={[
                { value: "closest", label: "Closest" },
                { value: "fewer_players", label: "Fewer players" },
              ]}
              onChange={(mode) => patch({ mode })}
            />
          </Row>
          <Row
            label="Preferred location"
            desc="Searched first. Automatic goes by measured ping."
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
              {allowed.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.city}, {c.country}
                </option>
              ))}
            </Select>
          </Row>
          <Row
            label="Free slots needed"
            desc="Only join servers with room for this many players."
          >
            <SliderInput
              ariaLabel="Minimum free slots"
              value={m.minimum_free_slots}
              min={1}
              max={20}
              disabled={busy}
              onChange={(minimum_free_slots) => patch({ minimum_free_slots })}
            />
          </Row>
          <Row
            label="Servers to check"
            desc="More takes longer but gives it more to choose from."
          >
            <SliderInput
              ariaLabel="Search limit"
              value={m.search_limit}
              min={10}
              max={200}
              step={10}
              disabled={busy}
              onChange={(search_limit) => patch({ search_limit })}
            />
          </Row>
          <Row
            label="Connect SwiftTunnel first"
            desc="Uses the relay that matches the server and disconnects when the game ends."
          >
            <Toggle
              enabled={m.prepare_tunnel}
              disabled={busy}
              ariaLabel="Matchmaker prepares tunnel"
              onChange={(prepare_tunnel) => patch({ prepare_tunnel })}
            />
          </Row>
          <Row
            label="Suggest a better server after joining"
            desc="Asks once per join. Ignore it and you stay where you are."
          >
            <Toggle
              enabled={m.offer_better_server}
              disabled={busy}
              ariaLabel="Offer a better server"
              onChange={(offer_better_server) => patch({ offer_better_server })}
            />
          </Row>
        </div>
      </Panel>
      <Panel
        eyebrow="Allowed locations"
        desc={`${allowed.length} of ${centers.length} allowed. A game's own preferred location still wins.`}
        actions={
          <Button
            size="sm"
            variant="secondary"
            disabled={busy || !m.blocked_datacenters.length}
            onClick={() => patch({ blocked_datacenters: [] })}
          >
            Allow all
          </Button>
        }
      >
        <label className="relative mb-3 block">
          <Icon
            name="search"
            size={13}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
          />
          <input
            aria-label="Find datacenter"
            placeholder="Find a city or country"
            className={`${compactFieldClass} w-full pl-8`}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <div className="flex flex-wrap gap-1.5">
          {shown.map((c) => {
            const on = !m.blocked_datacenters.includes(c.id);
            return (
              <button
                key={c.id}
                type="button"
                aria-pressed={on}
                aria-label={`Allow ${c.city}`}
                disabled={busy}
                onClick={() =>
                  patch({
                    blocked_datacenters: on
                      ? [...m.blocked_datacenters, c.id]
                      : m.blocked_datacenters.filter((id) => id !== c.id),
                    preferred_datacenter:
                      on && m.preferred_datacenter === c.id
                        ? null
                        : m.preferred_datacenter,
                  })
                }
                className={`flex items-center gap-2 rounded-[var(--radius-button)] border py-1.5 pl-2 pr-2.5 text-[11.5px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                  on
                    ? "border-border-default bg-bg-elevated text-text-primary"
                    : "border-border-subtle text-text-dimmed hover:text-text-muted"
                }`}
              >
                <span className={on ? "" : "opacity-35 grayscale"}>
                  <Flag code={c.country} size={15} />
                </span>
                {c.city}
                {on && (
                  <Icon
                    name="check"
                    size={11}
                    strokeWidth={2.6}
                    className="text-status-connected"
                  />
                )}
              </button>
            );
          })}
        </div>
        {!shown.length && (
          <p className="py-4 text-center text-[12px] text-text-muted">
            No location matches.
          </p>
        )}
      </Panel>
      <Panel
        eyebrow="Skipped games"
        desc="These always use normal Roblox matchmaking."
      >
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            addSkipped();
          }}
        >
          <input
            aria-label="Game link or place ID to skip"
            placeholder="Game link or place ID"
            maxLength={2048}
            className={`${compactFieldClass} flex-1`}
            value={skipInput}
            onChange={(e) => setSkipInput(e.target.value)}
          />
          <Button
            type="submit"
            size="sm"
            variant="secondary"
            disabled={busy || !skipPlace}
          >
            Add
          </Button>
        </form>
        {m.skipped_games.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {m.skipped_games.map((place) => {
              const name = games?.find((g) => g.place_id === place)?.name;
              return (
                <span
                  key={place}
                  className="flex items-center gap-1.5 rounded-[var(--radius-button)] border border-border-default bg-bg-elevated py-1 pl-2.5 pr-1 text-[11.5px] font-medium text-text-primary"
                >
                  {name ?? <span className="font-mono">{place}</span>}
                  <button
                    type="button"
                    aria-label={`Stop skipping ${name ?? place}`}
                    disabled={busy}
                    onClick={() =>
                      patch({
                        skipped_games: m.skipped_games.filter(
                          (old) => old !== place,
                        ),
                      })
                    }
                    className="grid h-5 w-5 place-items-center rounded-[4px] text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
                  >
                    <Icon name="close" size={11} strokeWidth={2.2} />
                  </button>
                </span>
              );
            })}
          </div>
        )}
      </Panel>
      <Panel flush>
        <Row
          label="Offer to rejoin after a crash"
          desc="Asks first. Never rejoins by itself."
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
      </Panel>
      <Panel
        eyebrow="Settings profiles"
        desc="Save your current FPS, graphics and FastFlags under a name, then pick it in a game's settings."
      >
        <div className="flex gap-2">
          <input
            aria-label="Profile name"
            placeholder="Profile name"
            maxLength={48}
            className={`${compactFieldClass} flex-1`}
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
        {config.profiles.length > 0 && (
          <div className="mt-3 divide-y divide-border-subtle rounded-[10px] bg-bg-base">
            {config.profiles.map((p) => (
              <Row
                key={p.name}
                label={p.name}
                desc={`${p.settings.unlock_fps ? p.settings.target_fps : 60} FPS · ${p.settings.graphics_quality} · ${p.settings.custom_fflags_enabled ? "Custom flags" : p.settings.ultraboost ? "Ultraboost" : "Default flags"}`}
              >
                <div className="flex gap-1">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() =>
                      void navigator.clipboard
                        .writeText(JSON.stringify(p, null, 2))
                        .then(
                          () => setNotice("Profile copied. Paste it to share."),
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
                </div>
              </Row>
            ))}
          </div>
        )}
      </Panel>
      <p className="px-1 text-[11px] text-text-muted">
        Server locations by{" "}
        <button
          type="button"
          className="text-text-secondary underline decoration-border-strong underline-offset-2 hover:text-text-primary"
          onClick={() => void systemOpenUrl("https://www.rovalra.com")}
        >
          RoValra
        </button>
        . Availability by Roblox.
      </p>
      {dirty && (
        <div className="surface-elevated sticky bottom-3 z-20 flex items-center justify-between gap-3 rounded-[var(--radius-card)] py-2.5 pl-4 pr-2.5">
          <p className="flex items-center gap-2.5 text-[12px] font-medium text-text-primary">
            <span className="h-1.5 w-1.5 rounded-full bg-text-muted" />
            Unsaved Matchmaker changes
          </p>
          <div className="flex gap-2">
            <Button
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() =>
                saved && setConfig({ ...saved, profiles: config.profiles })
              }
            >
              Discard
            </Button>
            <Button size="sm" loading={busy} onClick={() => void save(config)}>
              Save
            </Button>
          </div>
        </div>
      )}
      <Dialog
        open={importing}
        onClose={() => setImporting(false)}
        title="Import a profile"
        description="Paste a profile exported from SwiftTunnel. It is added to your list, not applied."
      >
        <div className="flex flex-col gap-4">
          <textarea
            aria-label="Profile JSON"
            rows={10}
            maxLength={16384}
            spellCheck={false}
            className="block w-full resize-y rounded-[10px] border border-border-subtle bg-bg-base p-3 font-mono text-[11px] leading-relaxed text-text-primary outline-none transition-colors focus-visible:border-border-focus"
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
          />
          {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
          <div className="flex justify-end gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={busy}
              onClick={() => setImporting(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              loading={busy}
              disabled={!raw.trim()}
              onClick={() => void importProfile()}
            >
              Add profile
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
