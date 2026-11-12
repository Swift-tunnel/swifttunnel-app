import { invoke } from "@tauri-apps/api/core";

export function reportUiFailure(page: string | null, error: unknown): void {
  const kind =
    error instanceof TypeError ? "type_error" :
    error instanceof ReferenceError ? "reference_error" :
    error instanceof RangeError ? "range_error" :
    error instanceof SyntaxError ? "syntax_error" :
    "other";
  // JS error text and stacks can include URLs, paths and user input.
  void invoke("system_record_ui_failure", { page, kind }).catch(() => {});
}
