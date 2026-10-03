import { RotateCw, TriangleAlert } from 'lucide-react';
import { isRouteErrorResponse, Link, useRouteError } from 'react-router';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/api-client';
import {
  describeError,
  isChunkLoadError,
  isNetworkError,
  type ErrorDescription,
} from '@/lib/errors';
import { cn } from '@/lib/utils';

interface RouteErrorPageProps {
  /**
   * `screen` fills the window, for an error above the app layout; `page` fills the content
   * area, so the sidebar stays and the user can go elsewhere.
   */
  variant?: 'screen' | 'page';
}

/** Boundary for a render or loader error: says what went wrong and offers a way out. */
export function RouteErrorPage({ variant = 'screen' }: RouteErrorPageProps) {
  const error = useRouteError();
  const { title, message } = routeErrorDescription(error);
  const detail = technicalDetail(error);

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-4 p-4 text-center',
        variant === 'screen' ? 'min-h-svh' : 'min-h-[60vh]',
      )}
    >
      <TriangleAlert className="text-destructive size-10" aria-hidden />
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p role="alert" className="text-muted-foreground max-w-md text-sm">
        {message}
      </p>
      <div className="flex flex-wrap justify-center gap-2">
        <Button onClick={() => window.location.reload()}>
          <RotateCw aria-hidden />
          Reload the page
        </Button>
        <Button asChild variant="outline">
          <Link to="/">Back to the dashboard</Link>
        </Button>
      </div>
      {detail && (
        <details className="text-muted-foreground max-w-md text-left text-xs">
          <summary className="cursor-pointer select-none">Technical details</summary>
          <pre className="bg-muted mt-2 overflow-auto rounded p-2 whitespace-pre-wrap">
            {detail}
          </pre>
        </details>
      )}
    </div>
  );
}

function routeErrorDescription(error: unknown): ErrorDescription {
  if (isRouteErrorResponse(error)) {
    if (error.status === 404) {
      return {
        title: 'Page not found',
        message: 'Nothing lives at this address.',
        retryable: false,
      };
    }
    return {
      title: 'Something went wrong',
      message: `The page could not be shown (${error.status} ${error.statusText}).`,
      retryable: true,
    };
  }
  if (error instanceof ApiError || isNetworkError(error) || isChunkLoadError(error)) {
    return describeError(error);
  }
  // Anything else is a bug in the page rather than a failed request.
  return {
    title: 'Something went wrong',
    message:
      'This page hit an unexpected error. Reload to try again; if it keeps happening, tell an administrator.',
    retryable: true,
  };
}

/** The raw error, for whoever is asked to look into it; nothing when it says no more. */
function technicalDetail(error: unknown): string | null {
  if (isRouteErrorResponse(error)) return null;
  if (error instanceof Error) return error.message || error.name;
  return typeof error === 'string' ? error : null;
}
