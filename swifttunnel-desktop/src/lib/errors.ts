export function formatErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return String(error);
}

const reportedErrors = new Set<string>();

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
    reportedErrors.add(dedupeKey);
  }

  console.warn(`[SwiftTunnel] ${context}: ${message}`);
}
