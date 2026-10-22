import { RotateCw, TriangleAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { describeError } from '@/lib/errors';
import { cn } from '@/lib/utils';

interface ErrorStateProps {
  error: unknown;

  what?: string;

  message?: string;

  onRetry?: () => void;

  retrying?: boolean;

  announce?: boolean;
  className?: string;
}

export function ErrorState({
  error,
  what,
  message,
  onRetry,
  retrying = false,
  announce = true,
  className,
}: ErrorStateProps) {
  const described = describeError(error, what);

  return (
    <div
      role={announce ? 'alert' : undefined}
      className={cn(
        'border-destructive/30 bg-destructive/5 flex flex-wrap items-start gap-3 rounded-md border p-3 text-sm',
        className,
      )}
    >
      <TriangleAlert className="text-destructive mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1 space-y-0.5">
        <p className="text-destructive font-medium">{described.title}</p>
        <p className="text-muted-foreground">{message ?? described.message}</p>
      </div>
      {onRetry && described.retryable && (
        <Button variant="outline" size="sm" onClick={onRetry} disabled={retrying}>
          <RotateCw className={retrying ? 'animate-spin' : undefined} aria-hidden />
          Try again
        </Button>
      )}
    </div>
  );
}
