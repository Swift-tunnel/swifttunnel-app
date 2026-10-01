export interface BulkItem {
  id: string;
  name: string;
  safety?: string;
}

/** Caution changes remain individual opt-ins, including the tier controls. */
export function bulkEnableTargets<T extends BulkItem>(items: T[]): T[] {
  return items.filter((item) => item.safety !== "caution");
}
