import { Component, type ErrorInfo, type ReactNode } from "react";
import { reportError } from "../../lib/errors";

/** Keep a broken optional page from taking the navigation and controls down. */
export class PageErrorBoundary extends Component<{
  page: string;
  children: ReactNode;
}, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    reportError(`Could not render ${this.props.page}`, error, {
      dedupeKey: `page-render-${this.props.page}`,
    });
    console.warn("[SwiftTunnel] Page component stack", info.componentStack);
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div role="alert" className="instrument flex flex-col gap-2 p-5">
        <h2 className="text-[14px] font-semibold text-text-primary">This page couldn't open.</h2>
        <p className="text-[12px] text-text-muted">
          Switch to another page using the sidebar. If this keeps happening, close and reopen SwiftTunnel.
        </p>
      </div>
    );
  }
}
