// Mock @tauri-apps/api/event for browser preview

export type UnlistenFn = () => void;

export async function listen<T>(
  _event: string,
  _handler: (event: { payload: T }) => void,
): Promise<UnlistenFn> {
  return () => {};
}

export async function emit(_event: string, _payload?: unknown): Promise<void> {}

/** Used by the overlay bus to target a specific window. Missing this export
 *  failed the whole ESM module graph and blanked browser-preview mode. */
export async function emitTo(
  _target: unknown,
  _event: string,
  _payload?: unknown,
): Promise<void> {}

export async function once<T>(
  _event: string,
  _handler: (event: { payload: T }) => void,
): Promise<UnlistenFn> {
  return () => {};
}
