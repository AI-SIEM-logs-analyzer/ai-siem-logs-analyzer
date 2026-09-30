import { FileUp, Upload } from 'lucide-react';
import { Can } from '@/components/auth/can';
import { ComingSoon } from '@/components/coming-soon';
import { PageHeader } from '@/components/page-header';

export function UploadsPage() {
  return (
    <>
      <PageHeader title="Uploads" description="Log files submitted for ingestion." />
      {/* Viewers follow uploads but cannot submit one: POST /api/logs/upload is ADMIN, ANALYST. */}
      <Can permission="logs:upload">
        <ComingSoon
          icon={FileUp}
          title="Upload a log file"
          description="Submit a log file for parsing — backed by POST /api/logs/upload."
        />
      </Can>
      <ComingSoon
        icon={Upload}
        title="Log uploads"
        description="Follow the parsing status of submitted files — backed by /api/logs/uploads."
      />
    </>
  );
}
