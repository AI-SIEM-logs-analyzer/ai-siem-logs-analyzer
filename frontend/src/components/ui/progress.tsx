import * as React from 'react';
import { cn } from '@/lib/utils';

interface ProgressProps extends Omit<React.ComponentProps<'div'>, 'children'> {
  /** 0–100; leave undefined for an indeterminate bar. */
  value?: number;
}

function Progress({ className, value, ...props }: ProgressProps) {
  const clamped = value === undefined ? undefined : Math.min(100, Math.max(0, value));
  return (
    <div
      data-slot="progress"
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={clamped === undefined ? undefined : Math.round(clamped)}
      className={cn('bg-primary/20 relative h-2 w-full overflow-hidden rounded-full', className)}
      {...props}
    >
      <div
        data-slot="progress-indicator"
        className={cn(
          'bg-primary h-full transition-[width] duration-200',
          clamped === undefined && 'w-1/3 animate-pulse',
        )}
        style={clamped === undefined ? undefined : { width: `${clamped}%` }}
      />
    </div>
  );
}

export { Progress };
