import { CircleCheck, CircleDot, CircleSlash, LoaderCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { ALERT_STATUS_LABELS, type AlertStatus } from '@/lib/alert-filters';

const STATUS = {
  NEW: { variant: 'default', icon: CircleDot },
  IN_PROGRESS: { variant: 'secondary', icon: LoaderCircle },
  RESOLVED: { variant: 'outline', icon: CircleCheck },
  FALSE_POSITIVE: { variant: 'outline', icon: CircleSlash },
} as const satisfies Record<AlertStatus, unknown>;

export function AlertStatusBadge({ status }: { status: AlertStatus | undefined }) {
  if (!status) return <Badge variant="outline">Unknown</Badge>;
  const { variant, icon: Icon } = STATUS[status];
  return (
    <Badge variant={variant}>
      <Icon aria-hidden />
      {ALERT_STATUS_LABELS[status]}
    </Badge>
  );
}
