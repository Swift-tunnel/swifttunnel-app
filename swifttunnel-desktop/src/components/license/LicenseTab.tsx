import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { systemOpenUrl } from "../../lib/commands";
import { useAuthStore } from "../../stores/authStore";
import "./license.css";

export type LicenseStatus = { state: "not_launched"; enforced: boolean } | {
  state: "ready"; enforced: boolean; tier: "free" | "plus" | "pro";
  unlimited: boolean; available_seconds: number | null; reserved_seconds: number | null;
  expires_at: string | null; resets_at: string | null; checked_at: string;
};
const date = (value: string | null) => value ? new Date(value).toLocaleString() : "Not applicable";
export const playtime = (seconds: number | null) => seconds === null ? "Unavailable" : `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`;

export function LicenseTab() {
  const userId = useAuthStore(s => s.userId);
  const [status, setStatus] = useState<LicenseStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const generation = useRef(0);
  useEffect(() => {
    const current = ++generation.current;
    setStatus(null); setError(null);
    if (!userId) { setBusy(false); return; }
    setBusy(true);
    invoke<LicenseStatus>("auth_license_status").then(value => {
      if (current === generation.current) setStatus(value);
    }).catch(() => {
      if (current === generation.current) setError("We couldn't check your license. Refresh to try again; this does not mean your key is invalid.");
    }).finally(() => { if (current === generation.current) setBusy(false); });
    return () => { generation.current++; };
  }, [userId, refresh]);
  const open = (path: string) => {
    void systemOpenUrl(`https://www.swifttunnel.net${path}`).catch(() => setError("Couldn't open your browser. Visit swifttunnel.net to manage your license."));
  };
  const ready = status?.state === "ready" ? status : null;
  return <section className="license-page">
    <header className="license-heading"><div><span className="license-eyebrow">YOUR ACCOUNT</span><h1>License & playtime</h1><p>Your access, all in one place.</p></div>
      <button disabled={busy || !userId} onClick={() => setRefresh(v => v + 1)}>{busy ? "Checking..." : "Refresh status"}</button></header>
    {error && <p role="alert" className="license-notice">{error}</p>}
    {!userId && <p className="license-notice">Sign in to view your license.</p>}
    {status?.state === "not_launched" && <p className="license-notice">Licenses are not available yet. Your existing connection rules still apply.</p>}
    {ready && <div className="license-account">
      <div className="license-plan"><span className="license-eyebrow">CURRENT PLAN</span><h2>{ready.tier === "pro" ? "SwiftTunnel Pro" : ready.tier === "plus" ? "SwiftTunnel Plus" : "Free access"}</h2>
        <p>{ready.unlimited ? "Unlimited play while your pass is active." : ready.available_seconds === 0 ? "No time available for new leases. Manage your license to see your options." : "Ready for your next session."}</p></div>
      <dl className="license-facts"><div><dt>Available playtime</dt><dd>{ready.unlimited ? "Unlimited" : playtime(ready.available_seconds)}</dd></div><div><dt>{ready.tier === "free" ? "Window resets" : "Pass expires"}</dt><dd>{date(ready.tier === "free" ? ready.resets_at : ready.expires_at)}</dd></div>
        {ready.tier === "plus" && <div><dt>Daily refill</dt><dd>{date(ready.resets_at)}</dd></div>}</dl>
      {!ready.unlimited && <p className="license-footnote">{playtime(ready.reserved_seconds)} already reserved. Available time excludes issued leases, so a running connection can continue while its lease remains valid.</p>}
      <p className="license-footnote">Checked {date(ready.checked_at)}. Refresh after redeeming a key.{!ready.enforced && " License enforcement has not launched."}</p>
    </div>}
    <div className="license-actions"><button onClick={() => open("/dashboard?section=license")}>Redeem or manage keys ↗</button><button onClick={() => open("/dashboard?section=sessions")}>Devices & sessions ↗</button></div>
    <article className="license-pro"><div className="license-pro-copy"><span className="license-eyebrow">SWIFTTUNNEL PRO</span><h2>No checkpoints.<br/><span>No daily time limit.</span></h2><p>Unlimited play on your PC and Android phone during your pass. One place to manage both.</p><div className="license-actions"><button className="license-primary" onClick={() => open("/pricing")}>Explore Pro ↗</button><button onClick={() => open("/pricing")}>Compare plans</button></div><small>Pass duration depends on your plan. Checkout opens at launch.</small></div><svg className="license-gem" viewBox="0 0 240 240" aria-hidden="true"><path fill="#4b478f" d="m30 75 45-40h90l45 40-90 140Z"/><path fill="#7771c1" d="m30 75 90 140-45-140Z"/><path fill="#262350" d="m165 75-45 140 90-140Z"/><path fill="#aaa2ef" d="m75 35 45 40H30Z"/><path fill="#635aa9" d="m75 35 45 40 45-40Z"/><path fill="#8d85cd" d="m165 35 45 40h-90Z"/><path fill="#3a346b" d="m75 75 45 140 45-140Z"/></svg></article>
  </section>;
}
