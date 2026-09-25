import { ScrollText } from 'lucide-react';
import { ComingSoon } from '@/components/coming-soon';
import { PageHeader } from '@/components/page-header';

export function EventsPage() {
  return (
    <>
      <PageHeader title="Events" description="Search normalized log events." />
      <ComingSoon
        icon={ScrollText}
        title="Event search"
        description="Filter by time, source, severity, source IP and HTTP status — backed by /api/events/search."
      />
    </>
  );
}
