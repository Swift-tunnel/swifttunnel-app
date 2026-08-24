/**
 * Stop the interface animating while the window is not in front.
 *
 * The UI has a fair amount of continuous motion: a drifting aurora wash,
 * rotating orbs, a route-flow dash, spinner rings and a panel sweep. All of it
 * is declared `infinite`, so the compositor repaints every frame for as long as
 * the app is open.
 *
 * WebView2 does not throttle that when the window goes to the background, and
 * measurably does not stop it when the window is *minimised* either: with the
 * main window minimised the GPU process still sat at ~32% of a core. So the
 * app was taking roughly a third of a CPU core, plus GPU time, away from
 * whatever game was running, purely to animate a window nobody could see.
 * Players reported exactly this and correctly blamed Edge WebView.
 *
 * `animation-play-state: paused` is the right lever rather than `display:none`
 * or unmounting: the compositor stops producing frames, but every element
 * keeps its layout and its current position, so restoring the window resumes
 * mid-drift instead of snapping.
 *
 * Transitions are deliberately left alone. They are one-shot and short, and
 * disabling them mid-flight makes state changes jump.
 *
 * Only the main window uses this. The in-game overlay is the one surface that
 * *should* keep animating while unfocused, since being unfocused is its entire
 * job.
 */

/** Class placed on the root element while animation is suspended. */
export const IDLE_CLASS = "app-idle";

/**
 * Whether motion should be suspended.
 *
 * Split out so the rule is testable without a DOM, and so the
 * `idle_when_unfocused` setting keeps working for anyone who deliberately
 * watches the app on a second monitor.
 */
export function shouldPauseAnimations(state: {
  idleWhenUnfocused: boolean;
  hasFocus: boolean;
}): boolean {
  if (!state.idleWhenUnfocused) return false;
  return !state.hasFocus;
}

/**
 * The bit of an element this module actually needs.
 *
 * Narrowed to a structural type because the suite runs on the node
 * environment with no DOM, matching the rest of `lib/`.
 */
export type ClassTarget = {
  classList: { toggle(token: string, force?: boolean): unknown; remove(token: string): unknown };
};

/**
 * Apply or lift the pause.
 *
 * Takes the element so it can be driven from a test, and returns whether the
 * class ended up applied.
 */
export function applyAnimationIdle(root: ClassTarget, paused: boolean): boolean {
  root.classList.toggle(IDLE_CLASS, paused);
  return paused;
}

/**
 * Wire the pause to focus changes.
 *
 * `focus`/`blur` on the window cover alt-tab, and `visibilitychange` covers
 * the cases where the webview itself is told it is hidden. Both end up asking
 * the same question, so they share a handler.
 */
export function installAnimationIdle(options: {
  isIdleEnabled: () => boolean;
  root?: ClassTarget;
  target?: Pick<Window, "addEventListener" | "removeEventListener">;
  doc?: Pick<Document, "hasFocus" | "addEventListener" | "removeEventListener">;
}): () => void {
  const root = options.root ?? document.documentElement;
  const target = options.target ?? window;
  const doc = options.doc ?? document;

  const sync = () => {
    applyAnimationIdle(
      root,
      shouldPauseAnimations({
        idleWhenUnfocused: options.isIdleEnabled(),
        hasFocus: doc.hasFocus(),
      }),
    );
  };

  target.addEventListener("focus", sync);
  target.addEventListener("blur", sync);
  doc.addEventListener("visibilitychange", sync);
  sync();

  return () => {
    target.removeEventListener("focus", sync);
    target.removeEventListener("blur", sync);
    doc.removeEventListener("visibilitychange", sync);
    root.classList.remove(IDLE_CLASS);
  };
}
