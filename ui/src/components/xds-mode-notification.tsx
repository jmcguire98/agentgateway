import { isXdsMode } from "@/lib/api";

export function XdsModeNotification() {
  if (!isXdsMode()) {
    return null;
  }

  return (
    <div className="bg-yellow-500 text-center p-2 text-sm">
      Configuration is managed by an external source (XDS). Editing the configuration is not allowed
      via the UI.
    </div>
  );
}
