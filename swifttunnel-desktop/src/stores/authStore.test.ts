import { beforeEach, describe, expect, it, vi } from "vitest";

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
});
