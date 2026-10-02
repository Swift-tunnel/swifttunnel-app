import { useState } from "react";
import { formatErrorMessage } from "../../lib/errors";
import { COMMUNITY_URL } from "../../lib/maintenance";
import { useToastStore } from "../../stores/toastStore";
import {
  settingsGenerateNetworkDiagnosticsBundle,
  systemCopyLogToClipboard,
  systemOpenUrl,
} from "../../lib/commands";
import { Button, InfoIcon, Row, Tooltip } from "../ui";
import { SupportSection } from "./SupportSection";

export function SupportToolsSection() {
  const addToast = useToastStore((s) => s.addToast);
  const [isGeneratingDiagnostics, setIsGeneratingDiagnostics] = useState(false);
  const [diagnosticsPath, setDiagnosticsPath] = useState<string | null>(null);
  const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null);
  const [isCopyingLog, setIsCopyingLog] = useState(false);
  const [copyLogPath, setCopyLogPath] = useState<string | null>(null);
  const [copyLogError, setCopyLogError] = useState<string | null>(null);

  async function generateDiagnosticsBundle() {
    if (isGeneratingDiagnostics) return;
    setIsGeneratingDiagnostics(true);
    setDiagnosticsError(null);
    setDiagnosticsPath(null);

    try {
      const response = await settingsGenerateNetworkDiagnosticsBundle();
      setDiagnosticsPath(response.file_path);
      addToast({ type: "success", message: "Diagnostics bundle generated" });

      try {
        await systemOpenUrl(response.folder_path);
      } catch (openError) {
        setDiagnosticsError(
          `Bundle saved at the path shown below, but its folder could not open: ${formatErrorMessage(openError)}`,
        );
      }
    } catch (error) {
      setDiagnosticsError(formatErrorMessage(error));
    } finally {
      setIsGeneratingDiagnostics(false);
    }
  }

  async function copyLogToClipboard() {
    if (isCopyingLog) return;
    setIsCopyingLog(true);
    setCopyLogError(null);
    setCopyLogPath(null);

    try {
      const response = await systemCopyLogToClipboard();
      setCopyLogPath(response.file_path);
      addToast({
        type: "success",
        message: "Log file copied, paste it into Discord or email.",
      });
    } catch (error) {
      setCopyLogError(formatErrorMessage(error));
    } finally {
      setIsCopyingLog(false);
    }
  }

  return (
    <SupportSection
      title="Support"
      tagElement={
        <button
          type="button"
          onClick={() =>
            void systemOpenUrl(COMMUNITY_URL).catch((error) => {
              addToast({ type: "error", message: `Could not open support: ${formatErrorMessage(error)}. Visit ${COMMUNITY_URL} in your browser.` });
            })
          }
          aria-label="Open SwiftTunnel Discord support server"
          className="inline-flex cursor-pointer items-center gap-1 rounded-[4px] px-1.5 py-[2px] font-mono text-[9.5px] font-medium transition-colors hover:bg-bg-hover active:scale-[0.98]"
          style={{
            backgroundColor: "var(--color-bg-elevated)",
            color: "var(--color-text-muted)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          <span>Contact support</span>
          <Tooltip content="Opens the SwiftTunnel Discord support server">
            <span className="inline-flex">
              <InfoIcon />
            </span>
          </Tooltip>
        </button>
      }
    >
      <Row
        label="Network diagnostics"
        desc="Generate a support-ready bundle with ISP, routing, and split tunnel info"
      >
        <Button
          variant="secondary"
          size="sm"
          onClick={() => void generateDiagnosticsBundle()}
          disabled={isGeneratingDiagnostics}
          loading={isGeneratingDiagnostics}
        >
          Generate
        </Button>
      </Row>
      {diagnosticsPath && <SupportPath label="Saved to" value={diagnosticsPath} />}
      {diagnosticsError && <SupportError value={diagnosticsError} />}

      <Row
        label="Copy log file"
        desc="Puts the SwiftTunnel log file on your clipboard"
      >
        <Button
          variant="secondary"
          size="sm"
          onClick={() => void copyLogToClipboard()}
          disabled={isCopyingLog}
          loading={isCopyingLog}
        >
          Copy
        </Button>
      </Row>
      {copyLogPath && <SupportPath label="Copied" value={copyLogPath} />}
      {copyLogError && <SupportError value={copyLogError} />}
    </SupportSection>
  );
}

function SupportPath({ label, value }: { label: string; value: string }) {
  return (
    <div className="px-4 pb-3 text-[11px] text-text-muted">
      {label}:{" "}
      <span className="break-all font-mono text-[10.5px] text-text-secondary">
        {value}
      </span>
    </div>
  );
}

function SupportError({ value }: { value: string }) {
  return <div className="px-4 pb-3 text-[11px] text-status-error">{value}</div>;
}
