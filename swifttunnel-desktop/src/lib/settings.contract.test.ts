import { describe, expect, it } from "vitest";
import backendSettingsSource from "../../src-tauri/src/commands/settings.rs?raw";
import coreSettingsSource from "../../../swifttunnel-core/src/settings.rs?raw";
import frontendTypesSource from "./types.ts?raw";

const RUST_SETTINGS_FIELDS = [
  "theme",
  "config",
  "window_state",
  "selected_region",
  "selected_server",
  "current_tab",
  "update_settings",
  "update_channel",
  "minimize_to_tray",
  "run_on_startup",
  "auto_reconnect",
  "resume_vpn_on_startup",
  "last_connected_region",
  "expanded_boost_info",
  "selected_game_presets",
  "network_test_results",
  "forced_servers",
  "artificial_latency_ms",
  "experimental_mode",
  "custom_relay_server",
  "enable_discord_rpc",
  "auto_routing_enabled",
  "whitelisted_regions",
  "preferred_physical_adapter_guid",
  "adapter_binding_mode",
  "game_process_performance",
  "roblox_network_bypass",
  "roblox_network_bypass_sni_fragment",
];

function extractInterfaceFields(source: string, interfaceName: string): string[] {
  const match = source.match(
    new RegExp(`export interface ${interfaceName} \\{([\\s\\S]*?)\\n\\}`, "m"),
  );
  if (!match) return [];

  return [...match[1].matchAll(/^\s*([a-zA-Z0-9_]+)\??:/gm)].map((m) => m[1]!);
}

describe("settings contract", () => {
  it("uses typed settings payloads at the Tauri boundary", () => {
    expect(backendSettingsSource).toMatch(
      /pub fn settings_load\(state: State<'_, AppState>\) -> Result<AppSettings, String>/,
    );
    expect(backendSettingsSource).toContain("settings: swifttunnel_core::settings::AppSettings");
    expect(backendSettingsSource).not.toContain("settings_json: String");
    expect(backendSettingsSource).not.toContain("SettingsResponse");
  });

  it("frontend AppSettings tracks serializable backend settings fields", () => {
    expect(coreSettingsSource).toContain("pub struct AppSettings");

    const frontendFields = new Set(extractInterfaceFields(frontendTypesSource, "AppSettings"));
    const missing = RUST_SETTINGS_FIELDS.filter((field) => !frontendFields.has(field));
    expect(missing).toEqual([]);
  });
});
