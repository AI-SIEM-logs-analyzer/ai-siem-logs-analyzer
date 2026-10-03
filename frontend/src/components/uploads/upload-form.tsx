import { useMutation, useQueryClient } from '@tanstack/react-query';
import { CircleCheck, CircleX, FileText, FileUp, X } from 'lucide-react';
import { useEffect, useId, useRef, useState, type DragEvent } from 'react';
import {
  checkFile,
  formatBytes,
  isSettled,
  UPLOAD_LIMITS,
  uploadErrorMessage,
  uploadKeys,
  uploadLogFile,
  useUpload,
  type LogUpload,
  type UploadProgress,
} from '@/api/uploads';
import { UploadStatusBadge } from '@/components/uploads/upload-status-badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { errorMessage } from '@/lib/errors';
import { cn } from '@/lib/utils';

/**
 * Picks a log file, sends it with a progress bar, then follows the upload's metadata until the
 * backend has parsed it or given up.
 */
export function UploadForm() {
  const queryClient = useQueryClient();
  const inputId = useId();
  const input = useRef<HTMLInputElement>(null);
  const controller = useRef<AbortController | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [rejection, setRejection] = useState<string | null>(null);
  const [progress, setProgress] = useState<UploadProgress | null>(null);
  const [dragging, setDragging] = useState(false);

  const upload = useMutation({
    mutationFn: (chosen: File) => {
      controller.current = new AbortController();
      return uploadLogFile(chosen, { onProgress: setProgress, signal: controller.current.signal });
    },
    onSuccess: (created) => {
      if (created.id !== undefined)
        queryClient.setQueryData(uploadKeys.detail(created.id), created);
      void queryClient.invalidateQueries({ queryKey: uploadKeys.all });
    },
    onSettled: () => {
      controller.current = null;
    },
  });

  // Leaving the page mid-upload stops sending the file.
  useEffect(() => () => controller.current?.abort(), []);

  function choose(chosen: File | undefined) {
    if (!chosen) return;
    upload.reset();
    setProgress(null);
    const problem = checkFile(chosen);
    setRejection(problem);
    setFile(problem ? null : chosen);
  }

  function clear() {
    upload.reset();
    setFile(null);
    setRejection(null);
    setProgress(null);
    if (input.current) input.current.value = '';
  }

  function onDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    if (!upload.isPending) choose(event.dataTransfer.files[0]);
  }

  const percent = progress && progress.total > 0 ? (progress.loaded / progress.total) * 100 : 0;
  const busy = upload.isPending;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileUp className="size-4" aria-hidden />
          <h2>Upload a log file</h2>
        </CardTitle>
        <CardDescription>
          {UPLOAD_LIMITS.extensions.map((e) => `.${e}`).join(', ')} up to{' '}
          {formatBytes(UPLOAD_LIMITS.maxFileSizeBytes)}. The format is detected from the content.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {upload.isSuccess ? (
          <UploadOutcome upload={upload.data} onAnother={clear} />
        ) : (
          <>
            <label
              htmlFor={inputId}
              onDragOver={(event) => {
                event.preventDefault();
                if (!busy) setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className={cn(
                'border-input hover:bg-accent/50 flex cursor-pointer flex-col items-center gap-2 rounded-lg border-2 border-dashed p-6 text-center text-sm transition-colors',
                dragging && 'border-primary bg-accent/50',
                busy && 'pointer-events-none opacity-60',
              )}
            >
              <FileUp className="text-muted-foreground size-6" aria-hidden />
              <span>
                <span className="font-medium">Choose a file</span> or drag it here
              </span>
              <input
                id={inputId}
                ref={input}
                type="file"
                aria-label="Log file"
                accept={UPLOAD_LIMITS.extensions.map((e) => `.${e}`).join(',')}
                className="sr-only"
                disabled={busy}
                onChange={(event) => choose(event.target.files?.[0])}
              />
            </label>

            {rejection && (
              <p role="alert" className="text-destructive flex items-center gap-2 text-sm">
                <CircleX className="size-4 shrink-0" aria-hidden />
                {rejection}
              </p>
            )}

            {file && (
              <div className="flex items-center gap-3 rounded-md border p-3 text-sm">
                <FileText className="text-muted-foreground size-5 shrink-0" aria-hidden />
                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className="flex justify-between gap-2">
                    <span className="truncate font-medium">{file.name}</span>
                    <span className="text-muted-foreground shrink-0">
                      {busy && progress
                        ? `${formatBytes(progress.loaded)} / ${formatBytes(progress.total)}`
                        : formatBytes(file.size)}
                    </span>
                  </div>
                  {busy && <Progress value={percent} aria-label={`Uploading ${file.name}`} />}
                </div>
                {!busy && (
                  <Button variant="ghost" size="icon-sm" onClick={clear} aria-label="Remove file">
                    <X />
                  </Button>
                )}
              </div>
            )}

            {upload.error && (
              <p role="alert" className="text-destructive flex items-center gap-2 text-sm">
                <CircleX className="size-4 shrink-0" aria-hidden />
                {uploadErrorMessage(upload.error)}
              </p>
            )}

            <div className="flex gap-2">
              <Button disabled={!file || busy} onClick={() => file && upload.mutate(file)}>
                {busy ? `Uploading… ${Math.round(percent)}%` : upload.error ? 'Retry' : 'Upload'}
              </Button>
              {busy && (
                <Button variant="outline" onClick={() => controller.current?.abort()}>
                  Cancel
                </Button>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

/** The accepted upload, followed by polling its metadata until parsing has finished. */
function UploadOutcome({ upload, onAnother }: { upload: LogUpload; onAnother: () => void }) {
  const queryClient = useQueryClient();
  const { data, error } = useUpload(upload.id);
  const current = data ?? upload;
  const settled = isSettled(current.status);

  // The listing below polls on its own, but only while it holds a row that is still in flight.
  useEffect(() => {
    if (settled) void queryClient.invalidateQueries({ queryKey: uploadKeys.all });
  }, [settled, queryClient]);

  return (
    <div className="space-y-3">
      <p role="status" className="flex items-center gap-2 text-sm">
        <CircleCheck className="size-4 shrink-0 text-emerald-600" aria-hidden />
        <span>
          <span className="font-medium">{current.fileName}</span> uploaded (
          {formatBytes(current.fileSize ?? 0)}).
        </span>
      </p>

      <div className="space-y-2 rounded-md border p-3 text-sm" aria-live="polite">
        <div className="flex items-center justify-between gap-2">
          <span className="text-muted-foreground">Processing</span>
          <UploadStatusBadge status={current.status} />
        </div>
        {!settled && (
          <Progress
            value={current.status === 'PENDING' ? 15 : undefined}
            aria-label="Processing progress"
          />
        )}
        <p className="text-muted-foreground">{statusDescription(current)}</p>
        {current.status === 'FAILED' && current.errorMessage && (
          <pre className="bg-muted text-destructive max-h-40 overflow-auto rounded p-2 text-xs whitespace-pre-wrap">
            {current.errorMessage}
          </pre>
        )}
        {error && (
          <p role="alert" className="text-destructive">
            Could not refresh the status. {errorMessage(error)}
          </p>
        )}
      </div>

      <Button variant="outline" onClick={onAnother}>
        Upload another file
      </Button>
    </div>
  );
}

function statusDescription(upload: LogUpload): string {
  const format = upload.detectedFormat ? ` as ${upload.detectedFormat}` : '';
  switch (upload.status) {
    case 'PENDING':
      return `Queued for parsing${format}.`;
    case 'PROCESSING':
      return `Parsing${format}…`;
    case 'INGESTED': {
      const count = upload.eventCount ?? 0;
      return `Parsed${format}: ${count.toLocaleString()} ${count === 1 ? 'event' : 'events'} indexed.`;
    }
    case 'FAILED':
      return 'Parsing failed.';
    default:
      return 'Waiting for the backend.';
  }
}
