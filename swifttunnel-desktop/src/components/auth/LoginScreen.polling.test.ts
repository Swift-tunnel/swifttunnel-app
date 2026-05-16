import { describe, expect, it } from "vitest";
import loginScreenSource from "./LoginScreen.tsx?raw";

function oauthPollingEffectSource() {
  const start = loginScreenSource.indexOf("let polling = false;");
  const end = loginScreenSource.indexOf("}, [cancelOAuth, isAwaiting, pollOAuth]);");
  return loginScreenSource.slice(start, end);
}

describe("LoginScreen OAuth polling lifecycle", () => {
  it("guards in-flight polling work after cleanup", () => {
    const source = oauthPollingEffectSource();

    expect(source).toContain("let disposed = false;");
    expect(source).toContain("disposed = true;");
    expect(source).toContain("if (polling || disposed) return;");
    expect(source).toContain("if (disposed) return;");
  });

  it("always releases the polling lock when the async interval callback exits", () => {
    const source = oauthPollingEffectSource();

    expect(source).toContain("try {");
    expect(source).toContain("} finally {");
    expect(source).toContain("polling = false;");
  });
});
