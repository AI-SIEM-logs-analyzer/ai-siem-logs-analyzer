import { Upload } from 'lucide-react';
import { ComingSoon } from '@/components/coming-soon';
import { PageHeader } from '@/components/page-header';

export function UploadsPage() {
  return (
    <>
      <PageHeader title="Uploads" description="Log files submitted for ingestion." />
      <ComingSoon
        icon={Upload}
        title="Log uploads"
        description="Upload log files and follow their parsing status — backed by /api/logs/uploads."
      />
    </>
  );
}
