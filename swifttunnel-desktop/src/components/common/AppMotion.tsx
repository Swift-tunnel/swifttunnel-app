import type { ReactNode } from "react";
import { domAnimation, LazyMotion, MotionConfig } from "framer-motion";

// The app uses fades/transforms and presence animations, not Motion's layout
// projection or drag engine. Keep the existing motion and reduced-motion policy
// with only the features it actually uses, available synchronously at mount.
export function AppMotion({ children }: { children: ReactNode }) {
  return <MotionConfig reducedMotion="user">
    <LazyMotion features={domAnimation} strict>{children}</LazyMotion>
  </MotionConfig>;
}
