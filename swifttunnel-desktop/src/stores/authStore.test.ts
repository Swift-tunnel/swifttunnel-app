import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthStateResponse, OAuthPollResult } from "../lib/types";

const commands = vi.hoisted(() => ({
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

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

function authState(overrides: Partial<AuthStateResponse>): AuthStateResponse {
  return {
    state: "logged_out",
    email: null,
    user_id: null,
    is_tester: false,
    is_banned: false,
    banned_reason: null,
    banned_at: null,
    ...overrides,
  };
}

describe("stores/authStore", () => {
  beforeEach(() => {
    Object.values(commands).forEach((mock) => mock.mockReset());
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

  it("does not let a stale fetch restore logged-in state after logout", async () => {
    const fetchState = deferred<AuthStateResponse>();
    commands.authGetState.mockReturnValueOnce(fetchState.promise);
    commands.authLogout.mockResolvedValueOnce(undefined);

    const useAuthStore = await loadStore();
    const fetchRun = useAuthStore.getState().fetchState();
    await Promise.resolve();

    await useAuthStore.getState().logout();

    fetchState.resolve(
      authState({
        state: "logged_in",
        email: "old@example.com",
        user_id: "old-user",
        is_tester: true,
      }),
    );
    await fetchRun;

    expect(useAuthStore.getState().state).toBe("logged_out");
    expect(useAuthStore.getState().email).toBeNull();
    expect(useAuthStore.getState().userId).toBeNull();
    expect(useAuthStore.getState().isTester).toBe(false);
    expect(useAuthStore.getState().isLoading).toBe(false);
  });

  it("does not let a stale OAuth poll failure overwrite cancellation", async () => {
    const poll = deferred<OAuthPollResult>();
    commands.authPollOAuth.mockReturnValueOnce(poll.promise);
    commands.authCancelOAuth.mockResolvedValueOnce(undefined);

    const useAuthStore = await loadStore();
    useAuthStore.setState((state) => ({
      ...state,
      state: "awaiting_oauth",
      isLoading: false,
      error: null,
    }));

    const pollRun = useAuthStore.getState().pollOAuth();
    await Promise.resolve();
    await useAuthStore.getState().cancelOAuth("Login cancelled.");

    poll.reject(new Error("old poll failed"));
    await expect(pollRun).resolves.toBe(false);

    expect(useAuthStore.getState().state).toBe("logged_out");
    expect(useAuthStore.getState().error).toBe("Login cancelled.");
  });
});
