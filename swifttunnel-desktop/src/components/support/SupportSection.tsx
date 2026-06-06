import type { ReactNode } from "react";
import { SectionHeader } from "../ui";

export function SupportSection({
  title,
  tagElement,
  children,
}: {
  title: string;
  tagElement?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section>
      {tagElement ? (
        <div className="mb-2.5 flex items-center gap-2">
          <h3 className="text-[12.5px] font-semibold text-text-primary">
            {title}
          </h3>
          {tagElement}
        </div>
      ) : (
        <SectionHeader label={title} />
      )}
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card divide-y divide-[color:var(--color-border-subtle)]">
        {children}
      </div>
    </section>
  );
}
