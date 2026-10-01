import { useState } from 'react';
import { formatBytes, useUploads } from '@/api/uploads';
import { UploadStatusBadge } from '@/components/uploads/upload-status-badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

const PAGE_SIZE = 20;

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** Every upload, newest first; rows still being parsed refresh on their own. */
export function UploadsTable() {
  const [page, setPage] = useState(0);
  const { data, error, isPending, isPlaceholderData } = useUploads(page, PAGE_SIZE);

  return (
    <Card className="gap-0 py-0">
      <CardHeader className="border-b py-4 [.border-b]:pb-4">
        <CardTitle>
          <h2>Log uploads</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="overflow-x-auto px-0">
        {isPending ? (
          <div className="space-y-2 p-4" aria-label="Loading uploads">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : error ? (
          <p role="alert" className="text-destructive p-4 text-sm">
            Could not load uploads: {error.message}
          </p>
        ) : !data.items?.length ? (
          <p className="text-muted-foreground p-4 text-sm">No log files have been uploaded yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-muted-foreground border-b text-left">
              <tr>
                <th className="px-4 py-3 font-medium">File</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Format</th>
                <th className="px-4 py-3 text-right font-medium">Size</th>
                <th className="px-4 py-3 text-right font-medium">Events</th>
                <th className="px-4 py-3 font-medium">Uploaded</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {data.items.map((upload) => (
                <tr key={upload.id}>
                  <td className="max-w-64 px-4 py-3">
                    <div className="truncate font-medium" title={upload.fileName}>
                      {upload.fileName}
                    </div>
                    {upload.status === 'FAILED' && upload.errorMessage && (
                      <div
                        className="text-destructive truncate text-xs"
                        title={upload.errorMessage}
                      >
                        {upload.errorMessage}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <UploadStatusBadge status={upload.status} />
                  </td>
                  <td className="text-muted-foreground px-4 py-3">
                    {upload.detectedFormat ?? '—'}
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums">
                    {upload.fileSize !== undefined ? formatBytes(upload.fileSize) : '—'}
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums">
                    {upload.status === 'INGESTED' ? (upload.eventCount ?? 0).toLocaleString() : '—'}
                  </td>
                  <td className="text-muted-foreground px-4 py-3 whitespace-nowrap">
                    {upload.createdAt ? dateTime.format(new Date(upload.createdAt)) : '—'}
                    {upload.uploadedBy && <span> by {upload.uploadedBy}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
      {data && (data.total ?? 0) > PAGE_SIZE && (
        <div className="flex items-center justify-between gap-2 border-t px-4 py-3 text-sm">
          <span className="text-muted-foreground">
            Page {page + 1} of {Math.ceil((data.total ?? 0) / PAGE_SIZE)}
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page === 0 || isPlaceholderData}
              onClick={() => setPage((p) => p - 1)}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={(page + 1) * PAGE_SIZE >= (data.total ?? 0) || isPlaceholderData}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}
