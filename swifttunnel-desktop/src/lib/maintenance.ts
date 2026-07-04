/**
 * Master maintenance switch.
 *
 * When `true`, every launch shows the full-screen maintenance page instead of
 * the app — no login, no backend calls, no connect attempts. Flip to `false`
 * (and ship a build) to return to normal operation once the service is back up.
 */
export const MAINTENANCE_MODE = true;

/** Where the "Join the community" button sends users for status updates. */
export const COMMUNITY_URL = "https://swifttunnel.net/discord";
