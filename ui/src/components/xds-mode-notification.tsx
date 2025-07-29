"use client";

import { isXdsMode, subscribeXdsMode } from "@/lib/api";
import { useEffect, useState } from "react";

export function XdsModeNotification() {
  const [xds, setXds] = useState(isXdsMode());

  useEffect(() => {
    return subscribeXdsMode(setXds);
  }, []);

  if (!xds) return null;

  return (
    <div className="bg-yellow-500 text-center p-2 text-sm">
      Configuration is managed by an external source (XDS). Editing the configuration is not allowed via the UI.
    </div>
  );
}
