import { useState } from "react";
import { motion } from "framer-motion";
import { BoostTab } from "../boost/BoostTab";
import { Button } from "../ui";

/** Optional bundled override: drop an image at `src/assets/games/<id>.<ext>`
 *  (png/jpg/jpeg/webp) and it wins over the remote `backgroundUrl`. */
const ART_BY_FILE = import.meta.glob<string>(
  "../../assets/games/*.{png,jpg,jpeg,webp}",
  { eager: true, query: "?url", import: "default" },
);

function bundledArt(id: string): string | undefined {
  const entry = Object.entries(ART_BY_FILE).find(([path]) =>
    path.includes(`/games/${id}.`),
  );
  return entry?.[1];
}

/** Games surfaced in the library. `backgroundUrl` is fetched art (Steam CDN for
 *  Steam titles, brand CDN otherwise — same approach as the games catalog).
 *  Built to take more entries without layout changes. */
const GAMES: {
  id: string;
  name: string;
  tagline: string;
  accent: string;
  backgroundUrl?: string;
}[] = [
  {
    id: "roblox",
    name: "Roblox",
    tagline: "FPS · latency · graphics",
    accent: "#e2231a",
    backgroundUrl: "https://images.rbxcdn.com/5348266ea6c5e67b19d6a814cbbb70f6.jpg",
  },
];

type GameId = (typeof GAMES)[number]["id"];
type Game = (typeof GAMES)[number];

function artForGame(game: Game): string | undefined {
  return bundledArt(game.id) ?? game.backgroundUrl;
}

/** Roblox tilted-square mark, used only when no artwork loads. */
function RobloxGlyph({ size = 56 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden>
      <g transform="rotate(-11 50 50)">
        <rect x="18" y="18" width="64" height="64" rx="8" fill="currentColor" />
        <rect x="41" y="41" width="18" height="18" rx="2" fill="var(--color-bg-base)" />
      </g>
    </svg>
  );
}

function GameCard({ game, onOptimize }: { game: Game; onOptimize: () => void }) {
  const [artFailed, setArtFailed] = useState(false);
  const art = artForGame(game);
  const showArt = art && !artFailed;

  return (
    <motion.article
      whileHover={{ y: -2 }}
      transition={{ duration: 0.15, ease: "easeOut" }}
      className="flex flex-col overflow-hidden rounded-[var(--radius-card)] surface-card"
    >
      {/* Art header (vertical, full-bleed cover art) */}
      <div
        className="relative w-full overflow-hidden"
        style={{
          height: "270px",
          borderBottom: "1px solid var(--color-border-subtle)",
          color: game.accent,
        }}
      >
        {showArt ? (
          <img
            src={art}
            alt={game.name}
            className="absolute inset-0 h-full w-full object-cover"
            onError={() => setArtFailed(true)}
          />
        ) : (
          <div
            className="absolute inset-0 flex items-center justify-center"
            style={{
              background: `radial-gradient(120% 120% at 50% 0%, ${game.accent}33, transparent 72%), linear-gradient(180deg, var(--color-bg-card), var(--color-bg-base))`,
            }}
          >
            <RobloxGlyph size={56} />
          </div>
        )}
      </div>

      {/* Body */}
      <div className="flex flex-1 flex-col gap-3 p-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[14px] font-semibold text-text-primary">
              {game.name}
            </span>
            <span
              className="rounded-[4px] px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-[0.08em]"
              style={{
                backgroundColor: "var(--color-status-connected-soft-10)",
                color: "var(--color-status-connected)",
              }}
            >
              Supported
            </span>
          </div>
          <p className="mt-1 text-[11.5px] leading-snug text-text-muted">
            {game.tagline}
          </p>
        </div>

        <Button
          variant="primary"
          size="sm"
          onClick={onOptimize}
          className="mt-auto w-full justify-center"
        >
          Optimize
        </Button>
      </div>
    </motion.article>
  );
}

export function GamesTab() {
  const [optimizing, setOptimizing] = useState<GameId | null>(null);

  if (optimizing) {
    const game = GAMES.find((g) => g.id === optimizing) ?? GAMES[0];
    return (
      <div>
        <button
          type="button"
          onClick={() => setOptimizing(null)}
          className="group mb-4 flex items-center gap-1.5 text-[12px] font-medium text-text-muted transition-colors hover:text-text-primary"
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M15 18l-6-6 6-6" />
          </svg>
          <span className="text-text-dimmed group-hover:text-text-secondary">
            Library
          </span>
          <span className="text-text-dimmed">/</span>
          <span>{game.name}</span>
        </button>
        <BoostTab />
      </div>
    );
  }

  return (
    <div>
      <div className="mb-5">
        <span className="eyebrow">Library</span>
        <h2 className="mt-3 text-[22px] font-semibold leading-none text-text-primary">
          Games
        </h2>
        <p className="mt-2 text-[12.5px] text-text-muted">
          Pick a game to tune its performance, graphics and latency.
        </p>
      </div>

      <div className="grid grid-cols-[repeat(auto-fill,minmax(240px,280px))] gap-4">
        {GAMES.map((game) => (
          <GameCard
            key={game.id}
            game={game}
            onOptimize={() => setOptimizing(game.id)}
          />
        ))}
      </div>
    </div>
  );
}
