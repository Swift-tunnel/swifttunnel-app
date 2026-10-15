import { create } from "zustand";
import type { AuthState, AuthStateEvent } from "../lib/types";
import {
  authGetState,
  authLogin,
  authStartOAuth,
  authPollOAuth,
  authCancelOAuth,
  authCompleteOAuth,
  authLogout,
  authRefreshProfile,
} from "../lib/commands";
import { reportError } from "../lib/errors";

// Reads may complete after a newer native event or account action. Only the
// latest read in the current revision may publish a snapshot or an error.
let authStateRevision = 0;
// Account actions have a separate generation: native events from the action
// itself may update the read revision while a request is still in flight.
let authActionRevision = 0;

function formatAuthError(error: unknown): string {
  const message = String(error);
  const lower = message.toLowerCase();

  if (
    lower.includes("network error") &&
    (lower.includes("auth.swifttunnel.net") ||
      lower.includes("swifttunnel.net"))
  ) {
    return "SwiftTunnel could not reach the login service from this PC. Try browser sign-in, then check antivirus, proxy, VPN, or DNS settings if it still fails.";
  }

  return message;
}

interface AuthStore {
  state: AuthState;
  email: string | null;
  userId: string | null;
  isTester: boolean;
  isBanned: boolean;
  bannedReason: string | null;
  bannedAt: string | null;
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchState: () => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  startOAuth: () => Promise<void>;
  pollOAuth: () => Promise<boolean>;
  cancelOAuth: (reason?: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshProfile: () => Promise<void>;
  handleStateEvent: (event: AuthStateEvent) => void;
}

export const useAuthStore = create<AuthStore>((set, get) => ({
  state: "logged_out",
  email: null,
  userId: null,
  isTester: false,
  isBanned: false,
  bannedReason: null,
  bannedAt: null,
  isLoading: true,
  error: null,

  fetchState: async () => {
    const revision = ++authStateRevision;
    try {
      const resp = await authGetState();
      if (revision !== authStateRevision) return;
      set({
        state: resp.state,
        email: resp.email,
        userId: resp.user_id,
        isTester: resp.is_tester,
        isBanned: resp.is_banned,
        bannedReason: resp.banned_reason,
        bannedAt: resp.banned_at,
        isLoading: false,
        error: null,
      });
    } catch (e) {
      if (revision !== authStateRevision) return;
      set({ isLoading: false, error: formatAuthError(e) });
    }
  },

  login: async (email, password) => {
    const action = ++authActionRevision;
    ++authStateRevision;
    try {
      set({ state: "logging_in", isLoading: true, error: null });
      await authLogin(email, password);
      if (action !== authActionRevision) return;
      await get().fetchState();
    } catch (e) {
      if (action !== authActionRevision) return;
      const message = formatAuthError(e);
      await get().fetchState();
      if (action !== authActionRevision) return;
      set({
        isLoading: false,
        error: message,
      });
    }
  },

  startOAuth: async () => {
    const action = ++authActionRevision;
    ++authStateRevision;
    try {
      set({ state: "awaiting_oauth", error: null });
      // Native auth command already opens the browser and tracks pending state.
      await authStartOAuth();
    } catch (e) {
      if (action !== authActionRevision) return;
      set({ state: "logged_out", error: formatAuthError(e) });
    }
  },

  pollOAuth: async () => {
    const action = authActionRevision;
    try {
      const result = await authPollOAuth();
      if (action !== authActionRevision || get().state !== "awaiting_oauth") return false;
      if (result.completed && result.token && result.state) {
        await authCompleteOAuth(result.token, result.state);
        if (action !== authActionRevision) return false;
        await get().fetchState();
        return action === authActionRevision && get().state === "logged_in";
      }
      return false;
    } catch (e) {
      if (action !== authActionRevision) return false;
      set({ error: formatAuthError(e) });
      return false;
    }
  },

  cancelOAuth: async (reason = "Login cancelled.") => {
    const action = ++authActionRevision;
    ++authStateRevision;
    try {
      await authCancelOAuth();
    } catch (error) {
      reportError("Failed to cancel OAuth flow", error, {
        dedupeKey: "auth-cancel-oauth",
      });
    }

    if (action !== authActionRevision) return;
    // Native cancellation only cancels a flow still waiting for the browser.
    // The callback may already have started an exchange or signed in while
    // cancellation waited for the auth lock. Preserve that authoritative event
    // instead of drawing a logged-out screen over a live native session.
    const state = get().state;
    if (state === "logging_in" || state === "logged_in" || state === "banned") return;
    ++authStateRevision;
    set({ state: "logged_out", isLoading: false, error: reason });
  },

  logout: async () => {
    const action = ++authActionRevision;
    ++authStateRevision;
    try {
      await authLogout();
      if (action !== authActionRevision) return;
      ++authStateRevision;
      set({
        state: "logged_out",
        email: null,
        userId: null,
        isTester: false,
        isBanned: false,
        bannedReason: null,
        bannedAt: null,
        isLoading: false,
        error: null,
      });
    } catch (e) {
      if (action !== authActionRevision) return;
      set({ error: formatAuthError(e) });
    }
  },

  refreshProfile: async () => {
    const action = authActionRevision;
    try {
      set({ error: null });
      await authRefreshProfile();
    } catch (e) {
      if (action !== authActionRevision) return;
      set({ error: formatAuthError(e) });
    }
  },

  handleStateEvent: (event) => {
    ++authStateRevision;
    const isBanned = Boolean(event.is_banned);

    set({
      state: event.state as AuthState,
      isLoading: event.state === "logging_in",
      email: event.email,
      userId: event.user_id,
      isBanned,
      bannedReason: event.banned_reason ?? null,
      bannedAt: event.banned_at ?? null,
      isTester: isBanned ? false : Boolean(event.is_tester),
    });
  },
}));
