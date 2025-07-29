"use client";

import { useServer } from "@/lib/server-context";
import { ConfigError } from "@/components/config-error";
import { subscribeXdsMode, isXdsMode } from "@/lib/api";
import { useState, useEffect } from "react";

interface ConfigErrorWrapperProps {
  children: React.ReactNode;
}

export function ConfigErrorWrapper({ children }: ConfigErrorWrapperProps) {
  const { configError } = useServer();
  const [xds, setXds] = useState<boolean>(false);

  useEffect(() => {
    // initialise with current value
    setXds(isXdsMode());
    return subscribeXdsMode(setXds);
  }, []);

  if (configError && !xds) {
    return <ConfigError error={configError} />;
  }

  return <>{children}</>;
}
