import { systemOpenUrl } from "./commands";
import { formatErrorMessage } from "./errors";
import { useToastStore } from "../stores/toastStore";

/** UI links report shell failures instead of leaving rejected click promises. */
export async function openSystemLink(target: string): Promise<void> {
  try {
    await systemOpenUrl(target);
  } catch (error) {
    useToastStore.getState().addToast({ type: "error", message: formatErrorMessage(error) });
  }
}
