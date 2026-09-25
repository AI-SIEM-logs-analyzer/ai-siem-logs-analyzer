import { ShieldAlert } from 'lucide-react';
import { ComingSoon } from '@/components/coming-soon';
import { PageHeader } from '@/components/page-header';

export function AlertsPage() {
  return (
    <>
      <PageHeader title="Alerts" description="Detections raised against ingested events." />
      <ComingSoon
        icon={ShieldAlert}
        title="Alerts"
        description="Arrives with the detection engine on the backend."
      />
    </>
  );
}
