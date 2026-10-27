import { useState } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { Button } from "./Button";
import { ErrorBanner } from "./ErrorBanner";

/** A failed save must remain recoverable after a toast or tab disappears. */
export function SettingsSaveNotice() {
  const error = useSettingsStore((state) => state.saveError);
  const warning = useSettingsStore((state) => state.saveWarning);
  const save = useSettingsStore((state) => state.save);
  const [saving, setSaving] = useState(false);
  if (!error && !warning) return null;

  async function retry() {
    if (saving) return;
    setSaving(true);
    try {
      await save(true);
    } catch {
      // The store retains the latest failure for this notice.
    } finally {
      setSaving(false);
    }
  }

  return <ErrorBanner tone={error ? "error" : "warning"} action={<Button size="sm" variant="secondary" disabled={saving} onClick={() => void retry()}>{saving ? "Saving..." : error ? "Retry saving" : "Retry startup setup"}</Button>}>
    {error ? <>Settings could not be saved: {error}. Some changes may already be active. Retry saving before closing SwiftTunnel.</> : warning}
  </ErrorBanner>;
}
