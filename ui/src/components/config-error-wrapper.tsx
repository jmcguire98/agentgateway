"use client";

import { useServer } from "@/lib/server-context";
import { ConfigError } from "@/components/config-error";
import { isXdsMode } from "@/lib/api";

interface ConfigErrorWrapperProps {
  children: React.ReactNode;
}

export function ConfigErrorWrapper({ children }: ConfigErrorWrapperProps) {
  const { configError } = useServer();
  if (configError && !isXdsMode()) {
    return <ConfigError error={configError} />;
  }

  return <>{children}</>;
}
