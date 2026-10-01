import { Can } from '@/components/auth/can';
import { PageHeader } from '@/components/page-header';
import { UploadForm } from '@/components/uploads/upload-form';
import { UploadsTable } from '@/components/uploads/uploads-table';

export function UploadsPage() {
  return (
    <>
      <PageHeader title="Uploads" description="Log files submitted for ingestion." />
      {/* Viewers follow uploads but cannot submit one: POST /api/logs/upload is ADMIN, ANALYST. */}
      <Can permission="logs:upload">
        <UploadForm />
      </Can>
      <UploadsTable />
    </>
  );
}
