/** Shown in place of a fault in the app's own script. */
export const APP_FAULT_MESSAGE =
  "SwiftTunnel hit an unexpected problem. Try again. If it keeps happening, copy diagnostics from Repair and send them to support.";

/**
 * A fault in the app's own script, such as reading a field of `undefined`.
 * Its text ("Cannot read properties of undefined (reading 'entries')") tells
 * a player nothing and reads as broken English.
 *
 * Matched on the wording as well as the type: a failed network request is a
 * `TypeError` too, and "Failed to fetch" is worth showing as it is.
 */
function isScriptFault(error: unknown): error is Error {
  return (
    (error instanceof TypeError || error instanceof ReferenceError) &&
    /Cannot read propert|Cannot set propert|is not a function|is not defined|is not iterable|Cannot destructure|(undefined|null) is not an object/.test(
      error.message,
    )
  );
}

export function formatErrorMessage(error: unknown): string {
  if (isScriptFault(error)) {
    // Keep the real text where a developer can find it.
    console.warn(`[SwiftTunnel] script fault: ${error.message}`);
    return APP_FAULT_MESSAGE;
  }
  // IPC and browser libraries can reject with plain objects, not Error.
  // Never show "[object Object]", null or an empty notice as the explanation.
  let message: string | undefined;
  if (typeof error === "string") message = error;
  else if (error && typeof error === "object") {
    const value = error as { message?: unknown; error?: unknown };
    if (typeof value.message === "string") message = value.message;
    else if (typeof value.error === "string") message = value.error;
  }
  const text = message?.trim();
  if (!text) return "Something went wrong. Please try again.";
  return text.length > 4096 ? `${text.slice(0, 4096)}...` : text;
}

const reportedErrors = new Set<string>();
const MAX_REPORTED_ERRORS = 256;

export function reportError(
  context: string,
  error: unknown,
  options?: { dedupeKey?: string },
) {
  const message = formatErrorMessage(error);
  const dedupeKey = options?.dedupeKey
    ? `${options.dedupeKey}:${message}`
    : null;

  if (dedupeKey && reportedErrors.has(dedupeKey)) {
    return;
  }
  if (dedupeKey) {
    if (reportedErrors.size >= MAX_REPORTED_ERRORS) {
      const oldest = reportedErrors.values().next().value;
      if (oldest !== undefined) reportedErrors.delete(oldest);
    }
    reportedErrors.add(dedupeKey);
  }

  console.warn(`[SwiftTunnel] ${context}: ${message}`);
}
