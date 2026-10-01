import { CircleCheck, CircleX, Clock, LoaderCircle } from 'lucide-react';
import type { LogUploadStatus } from '@/api/uploads';
import { Badge } from '@/components/ui/badge';

const STATUS = {
  PENDING: { label: 'Queued', variant: 'outline', icon: Clock, spin: false },
  PROCESSING: { label: 'Parsing', variant: 'secondary', icon: LoaderCircle, spin: true },
  INGESTED: { label: 'Ingested', variant: 'default', icon: CircleCheck, spin: false },
  FAILED: { label: 'Failed', variant: 'destructive', icon: CircleX, spin: false },
} as const satisfies Record<LogUploadStatus, unknown>;

export function UploadStatusBadge({ status }: { status: LogUploadStatus | undefined }) {
  if (!status) return <Badge variant="outline">Unknown</Badge>;
  const { label, variant, icon: Icon, spin } = STATUS[status];
  return (
    <Badge variant={variant}>
      <Icon className={spin ? 'animate-spin' : undefined} aria-hidden />
      {label}
    </Badge>
  );
}
