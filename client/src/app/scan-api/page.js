"use client";

import { ScanApiAuditorView } from "../../components/ScanApiAuditorView";
import { DastUnavailable } from "../../components/DastUnavailable";
import { isDastEnabled } from "../../lib/featureFlags";

export default function ScanApiPage() {
  if (!isDastEnabled()) {
    return <DastUnavailable title="Auditor API no disponible" />;
  }
  return <ScanApiAuditorView />;
}
