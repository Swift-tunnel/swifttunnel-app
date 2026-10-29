import { expect, it, vi } from "vitest";
import { handleTabShortcut } from "./tabShortcuts";
import { NAV_ITEMS } from "../components/shell/nav";

function event(patch: Partial<Parameters<typeof handleTabShortcut>[0]> = {}) {
  return {
    key: "3", ctrlKey: true, metaKey: false, altKey: false, shiftKey: false,
    repeat: false, isComposing: false, defaultPrevented: false, target: null,
    preventDefault: vi.fn(), ...patch,
  };
}

it("uses the advertised sidebar mapping for Ctrl and Command navigation", () => {
  for (const item of NAV_ITEMS) {
    for (const command of [false, true]) {
      const navigate = vi.fn();
      const input = event({ key: item.shortcut, ctrlKey: !command, metaKey: command });
      handleTabShortcut(input, navigate);
      expect(navigate).toHaveBeenCalledExactlyOnceWith(item.id);
      expect(input.preventDefault).toHaveBeenCalledOnce();
    }
  }
});

it("leaves editing, consumed keys, composition and key repeats alone", () => {
  const closest = vi.fn().mockReturnValue({});
  const editable = { closest } as unknown as EventTarget;
  for (const patch of [
    { target: editable }, { defaultPrevented: true }, { repeat: true },
    { isComposing: true }, { altKey: true }, { shiftKey: true },
    { ctrlKey: false }, { key: "k" },
  ]) {
    const navigate = vi.fn();
    const input = event(patch);
    handleTabShortcut(input, navigate);
    expect(navigate).not.toHaveBeenCalled();
    expect(input.preventDefault).not.toHaveBeenCalled();
  }
  expect(closest.mock.calls[0][0]).toContain("textarea");
  expect(closest.mock.calls[0][0]).toContain("[contenteditable]");
  expect(closest.mock.calls[0][0]).toContain("select");
});

it("accepts shortcuts from ordinary content or the window itself", () => {
  for (const target of [null, {}, { closest: () => null }]) {
    const navigate = vi.fn();
    handleTabShortcut(event({ target: target as EventTarget | null }), navigate);
    expect(navigate).toHaveBeenCalledExactlyOnceWith("games");
  }
});
