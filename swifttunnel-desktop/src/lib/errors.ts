export function formatErrorMessage(error: unknown): string {
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
