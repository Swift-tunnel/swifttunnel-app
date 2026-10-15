import { beforeEach, describe, expect, it, vi } from "vitest";

const commands = vi.hoisted(() => ({
  authLogin: vi.fn(),
  authGetState: vi.fn(),
  authStartOAuth: vi.fn(),
  authPollOAuth: vi.fn(),
  authCancelOAuth: vi.fn(),
  authCompleteOAuth: vi.fn(),
  authLogout: vi.fn(),
  authRefreshProfile: vi.fn(),
}));

vi.mock("../lib/commands", () => commands);

vi.mock("../lib/errors", () => ({
  reportError: vi.fn(),
}));

async function loadStore() {
  vi.resetModules();
  return (await import("./authStore")).useAuthStore;
}

describe("stores/authStore", () => {
  beforeEach(() => {
    Object.values(commands).forEach((mock) => mock.mockReset());
  });

  const signedIn = {
    state: "logged_in" as const, email: "player@example.test", user_id: "player",
    is_tester: false, is_banned: false, banned_reason: null, banned_at: null,
  };

  it("does not exchange a late callback after OAuth is cancelled", async () => {
    let finish!: (result: { completed: boolean; token: string; state: string }) => void;
    commands.authPollOAuth.mockReturnValue(new Promise(resolve => { finish = resolve; }));
    commands.authStartOAuth.mockResolvedValue(undefined);
    commands.authCancelOAuth.mockResolvedValue(undefined);
    const store = await loadStore();
    await store.getState().startOAuth();
    const poll = store.getState().pollOAuth();
    await store.getState().cancelOAuth();
    finish({ completed: true, token: "test-exchange", state: "test-state" });
    expect(await poll).toBe(false);
    expect(commands.authCompleteOAuth).not.toHaveBeenCalled();
    expect(store.getState().state).toBe("logged_out");
    expect(store.getState().error).toBe("Login cancelled.");
  });

  it("does not let an earlier cancel undo a newly started browser sign-in", async () => {
    let finish!: () => void;
    commands.authCancelOAuth.mockReturnValue(new Promise<void>(resolve => { finish = resolve; }));
    commands.authStartOAuth.mockResolvedValue(undefined);
    const store = await loadStore();
    await store.getState().startOAuth();
    const cancel = store.getState().cancelOAuth();
    await store.getState().startOAuth();
    finish();
    await cancel;
    expect(store.getState().state).toBe("awaiting_oauth");
    expect(store.getState().error).toBeNull();
  });

  it.each(["logging_in", "logged_in", "banned"] as const)("does not overwrite native %s when cancellation completes late", async (state) => {
    let finish!: () => void;
    commands.authStartOAuth.mockResolvedValue(undefined);
    commands.authCancelOAuth.mockReturnValue(new Promise<void>(resolve => { finish = resolve; }));
    const store = await loadStore();
    await store.getState().startOAuth();
    const cancel = store.getState().cancelOAuth();
    store.getState().handleStateEvent({ ...signedIn, state, is_banned: state === "banned" });
    finish();
    await cancel;
    expect(store.getState().state).toBe(state);
    expect(store.getState().isLoading).toBe(state === "logging_in");
    expect(store.getState().userId).toBe("player");
    expect(store.getState().error).toBeNull();
  });

  it("does not report an old OAuth poll as completed after cancellation during its final read", async () => {
    let finish!: (value: typeof signedIn) => void;
    let readStarted!: () => void;
    const reading = new Promise<void>(resolve => { readStarted = resolve; });
    commands.authStartOAuth.mockResolvedValue(undefined);
    commands.authPollOAuth.mockResolvedValue({ completed: true, token: "exchange", state: "state" });
    commands.authCompleteOAuth.mockResolvedValue(undefined);
    commands.authCancelOAuth.mockResolvedValue(undefined);
    commands.authGetState.mockImplementation(() => {
      readStarted();
      return new Promise(resolve => { finish = resolve; });
    });
    const store = await loadStore();
    await store.getState().startOAuth();
    const poll = store.getState().pollOAuth();
    await reading;
    await store.getState().cancelOAuth();
    finish(signedIn);
    expect(await poll).toBe(false);
    expect(store.getState().state).toBe("logged_out");
  });

  it("ignores a failed old browser start after a new sign-in starts", async () => {
    let fail!: (error: Error) => void;
    commands.authStartOAuth.mockReturnValueOnce(new Promise((_resolve, reject) => { fail = reject; }))
      .mockResolvedValueOnce(undefined);
    const store = await loadStore();
    const older = store.getState().startOAuth();
    await store.getState().startOAuth();
    fail(new Error("Old browser failed"));
    await older;
    expect(store.getState().state).toBe("awaiting_oauth");
    expect(store.getState().error).toBeNull();
  });

  it("does not publish an old password error after logout", async () => {
    let fail!: (error: Error) => void;
    commands.authLogin.mockReturnValue(new Promise((_resolve, reject) => { fail = reject; }));
    commands.authLogout.mockResolvedValue(undefined);
    const store = await loadStore();
    const login = store.getState().login("player@example.test", "test-password");
    await store.getState().logout();
    fail(new Error("Old login failed"));
    await login;
    expect(commands.authGetState).not.toHaveBeenCalled();
    expect(store.getState().state).toBe("logged_out");
    expect(store.getState().error).toBeNull();
  });

  it("does not restore a signed-in snapshot after logout", async () => {
    let finish!: (value: typeof signedIn) => void;
    commands.authGetState.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    commands.authLogout.mockResolvedValue(undefined);
    const store = await loadStore();
    const read = store.getState().fetchState();
    await store.getState().logout();
    finish(signedIn);
    await read;
    expect(store.getState().state).toBe("logged_out");
    expect(store.getState().email).toBeNull();
    expect(store.getState().isLoading).toBe(false);
  });

  it("does not overwrite a newer ban event with an earlier snapshot", async () => {
    let finish!: (value: typeof signedIn) => void;
    commands.authGetState.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const store = await loadStore();
    const read = store.getState().fetchState();
    store.getState().handleStateEvent({ ...signedIn, state: "banned", is_banned: true, banned_reason: "restricted" });
    finish(signedIn);
    await read;
    expect(store.getState().state).toBe("banned");
    expect(store.getState().isBanned).toBe(true);
    expect(store.getState().isLoading).toBe(false);
  });

  it("ignores a failed old read after a newer auth event", async () => {
    let fail!: (error: Error) => void;
    commands.authGetState.mockReturnValue(new Promise((_resolve, reject) => { fail = reject; }));
    const store = await loadStore();
    const read = store.getState().fetchState();
    store.getState().handleStateEvent(signedIn);
    fail(new Error("old request failed"));
    await read;
    expect(store.getState().error).toBeNull();
    expect(store.getState().isLoading).toBe(false);
  });

  it("keeps the newer snapshot when reads finish out of order", async () => {
    let finish!: (value: typeof signedIn) => void;
    commands.authGetState.mockReturnValueOnce(new Promise((resolve) => { finish = resolve; }));
    commands.authGetState.mockResolvedValueOnce({ ...signedIn, email: "new@example.test", user_id: "new" });
    const store = await loadStore();
    const older = store.getState().fetchState();
    await store.getState().fetchState();
    finish(signedIn);
    await older;
    expect(store.getState().userId).toBe("new");
  });

  it("updates tester status from auth state events after a ban transition", async () => {
    const useAuthStore = await loadStore();

    useAuthStore.getState().handleStateEvent({
      state: "banned",
      email: "tester@example.com",
      user_id: "user-1",
      is_tester: true,
      is_banned: true,
      banned_reason: "abuse",
      banned_at: "2026-05-07T00:00:00.000Z",
    });

    expect(useAuthStore.getState().isTester).toBe(false);
    expect(useAuthStore.getState().isBanned).toBe(true);

    useAuthStore.getState().handleStateEvent({
      state: "logged_in",
      email: "tester@example.com",
      user_id: "user-1",
      is_tester: true,
      is_banned: false,
      banned_reason: null,
      banned_at: null,
    });

    expect(useAuthStore.getState().isTester).toBe(true);
    expect(useAuthStore.getState().isBanned).toBe(false);
  });

  it("surfaces refresh failures and clears stale refresh errors on retry", async () => {
    commands.authRefreshProfile
      .mockRejectedValueOnce(new Error("network down"))
      .mockResolvedValueOnce(undefined);

    const useAuthStore = await loadStore();

    await useAuthStore.getState().refreshProfile();
    expect(useAuthStore.getState().error).toBe("Error: network down");

    await useAuthStore.getState().refreshProfile();
    expect(useAuthStore.getState().error).toBeNull();
  });
});
