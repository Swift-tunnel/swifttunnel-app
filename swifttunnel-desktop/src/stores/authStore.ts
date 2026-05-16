import { create } from "zustand";
import type { AuthState, AuthStateEvent } from "../lib/types";
import {
  authGetState,
  authStartOAuth,
  authPollOAuth,
  authCancelOAuth,
  authCompleteOAuth,
  authLogout,
  authRefreshProfile,
} from "../lib/commands";
import { reportError } from "../lib/errors";

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
  startOAuth: () => Promise<void>;
  pollOAuth: () => Promise<boolean>;
  cancelOAuth: (reason?: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshProfile: () => Promise<void>;
  handleStateEvent: (event: AuthStateEvent) => void;
}

export const useAuthStore = create<AuthStore>((set, get) => {
  let authRunSeq = 0;

  return {
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
      const runId = ++authRunSeq;
      try {
        const resp = await authGetState();
        if (runId === authRunSeq) {
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
        }
      } catch (e) {
        if (runId === authRunSeq) {
          set({ isLoading: false, error: String(e) });
        }
      }
    },

    startOAuth: async () => {
      const runId = ++authRunSeq;
      try {
        set({ state: "awaiting_oauth", isLoading: false, error: null });
        // Native auth command already opens the browser and tracks pending state.
        await authStartOAuth();
      } catch (e) {
        if (runId === authRunSeq) {
          set({ state: "logged_out", isLoading: false, error: String(e) });
        }
      }
    },

    pollOAuth: async () => {
      const runId = ++authRunSeq;
      try {
        const result = await authPollOAuth();
        if (runId !== authRunSeq) return false;

        if (result.completed && result.token && result.state) {
          await authCompleteOAuth(result.token, result.state);
          if (runId !== authRunSeq) return false;

          await get().fetchState();
          return get().state === "logged_in" || get().state === "banned";
        }
        return false;
      } catch (e) {
        if (runId === authRunSeq) {
          set({ error: String(e) });
        }
        return false;
      }
    },

    cancelOAuth: async (reason = "Login cancelled.") => {
      const runId = ++authRunSeq;
      try {
        await authCancelOAuth();
      } catch (error) {
        reportError("Failed to cancel OAuth flow", error, {
          dedupeKey: "auth-cancel-oauth",
        });
      }

      if (runId === authRunSeq) {
        set({
          state: "logged_out",
          isLoading: false,
          error: reason,
        });
      }
    },

    logout: async () => {
      const runId = ++authRunSeq;
      try {
        await authLogout();
        if (runId === authRunSeq) {
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
        }
      } catch (e) {
        if (runId === authRunSeq) {
          set({ isLoading: false, error: String(e) });
        }
      }
    },

    refreshProfile: async () => {
      const runId = ++authRunSeq;
      try {
        set({ error: null });
        await authRefreshProfile();
        if (runId === authRunSeq) {
          set({ isLoading: false, error: null });
        }
      } catch (e) {
        if (runId === authRunSeq) {
          set({ error: String(e) });
        }
      }
    },

    handleStateEvent: (event) => {
      authRunSeq++;
      const isBanned = Boolean(event.is_banned);

      set({
        state: event.state as AuthState,
        email: event.email,
        userId: event.user_id,
        isLoading: false,
        isBanned,
        bannedReason: event.banned_reason ?? null,
        bannedAt: event.banned_at ?? null,
        isTester: isBanned ? false : Boolean(event.is_tester),
      });
    },
  };
});
