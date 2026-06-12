"use client";

import { EndpointProbeView } from "../../components/EndpointProbeView";
import { DastUnavailable } from "../../components/DastUnavailable";
import { isDastEnabled } from "../../lib/featureFlags";

export default function ProbePage() {
  if (!isDastEnabled()) {
    return <DastUnavailable title="Probe HTTP no disponible" />;
  }
  return <EndpointProbeView />;
}
