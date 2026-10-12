import { Sidebar } from "../components/shell/Sidebar";
import { GamesTab } from "../components/boost/GamesTab";
import { useAuthStore } from "../stores/authStore";
import { useSettingsStore } from "../stores/settingsStore";
useAuthStore.setState({ state: "logged_in", isLoading: false, email: "local-preview@example.invalid", userId: "preview" });
useSettingsStore.setState({ activeTab: "games", isLoaded: true });
export function GamePreview() {
  return <div className="flex h-screen w-screen overflow-hidden bg-bg-base"><Sidebar /><main className="min-w-0 flex-1 overflow-y-auto">
    <div className="border-b border-border-subtle px-6 py-3 text-[11px] text-text-muted">Design preview · sample data · actions simulated</div>
    <div className="mx-auto max-w-[1100px] p-5"><GamesTab /></div>
  </main></div>;
}
