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

interface AuthStore {
  state: AuthState;
  email: string | null;
  userId: string | null;
  isTester: boolean;
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

export const useAuthStore = create<AuthStore>((set, get) => ({
  state: "logged_out",
  email: null,
  userId: null,
  isTester: false,
  isLoading: true,
  error: null,

  fetchState: async () => {
    try {
      const resp = await authGetState();
      set({
        state: resp.state,
        email: resp.email,
        userId: resp.user_id,
        isTester: resp.is_tester,
        isLoading: false,
        error: null,
      });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
    }
  },

  startOAuth: async () => {
    try {
      set({ state: "awaiting_oauth", error: null });
      const authUrl = await authStartOAuth();
      // Tauri will open the URL in the default browser
      const { open } = await import("@tauri-apps/plugin-shell");
      await open(authUrl);
    } catch (e) {
      set({ state: "logged_out", error: String(e) });
    }
  },

  pollOAuth: async () => {
    try {
      const result = await authPollOAuth();
      if (result.completed && result.token && result.state) {
        await authCompleteOAuth(result.token, result.state);
        await get().fetchState();
        return true;
      }
      return false;
    } catch (e) {
      set({ error: String(e) });
      return false;
    }
  },

  cancelOAuth: async (reason = "Login cancelled.") => {
    try {
      await authCancelOAuth();
    } catch {
      // Best-effort cancel; local UI state still resets below.
    }

    set({
      state: "logged_out",
      error: reason,
    });
  },

  logout: async () => {
    try {
      await authLogout();
      set({
        state: "logged_out",
        email: null,
        userId: null,
        isTester: false,
        error: null,
      });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  refreshProfile: async () => {
    try {
      await authRefreshProfile();
      await get().fetchState();
    } catch (e) {
      set({ error: String(e) });
    }
  },

  handleStateEvent: (event) => {
    set({
      state: event.state as AuthState,
      email: event.email,
      userId: event.user_id,
    });
  },
}));
