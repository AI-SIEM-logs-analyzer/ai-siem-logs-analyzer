import { ApiError } from '@/lib/api-client';

// What a failure means to the person looking at the screen. Raw messages ("/api/users failed
// with 500", "Failed to fetch") name the plumbing; these name what happened and what to do.
// A screen with a more precise story for one status (a 503 from the search index, a 413 on
// upload) checks for it first and falls back to `errorMessage` for everything else.

/** A failure explained: a short headline, a sentence of detail, and whether trying again can help. */
export interface ErrorDescription {
  title: string;
  message: string;
  retryable: boolean;
}

/**
 * The request never got an answer: offline, DNS, CORS, the backend down behind the proxy.
 * `fetch` rejects with a `TypeError` whose wording each browser picks; a `TypeError` from a bug
 * ("Cannot read properties of undefined") is not one of these.
 */
export function isNetworkError(error: unknown): boolean {
  if (error instanceof DOMException) return error.name === 'NetworkError';
  return (
    error instanceof TypeError &&
    !isChunkLoadError(error) &&
    /failed to fetch|networkerror|network error|load failed|network request failed/i.test(
      error.message,
    )
  );
}

/**
 * A lazily loaded chunk that no longer exists, almost always because a new version was
 * deployed while this tab was open. Browsers word it differently; these cover Chromium,
 * Firefox, Safari and Vite's own preload error.
 */
export function isChunkLoadError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return /dynamically imported module|module script failed|importing a module script|error loading dynamically|preload css|unable to preload/i.test(
    error.message,
  );
}

/** The `message` a backend error body carries, or its text when it was not JSON. */
export function backendMessage(body: unknown): string | null {
  if (typeof body === 'string') return body.trim() || null;
  if (body && typeof body === 'object' && 'message' in body && typeof body.message === 'string') {
    return body.message.trim() || null;
  }
  return null;
}

/** How long a 429 or 503 asks to wait, from `Retry-After` in seconds; `null` without one. */
export function retryAfterSeconds(error: ApiError): number | null {
  const seconds = Number(error.headers.get('Retry-After'));
  return Number.isFinite(seconds) && seconds > 0 ? seconds : null;
}

function waitHint(error: ApiError): string {
  const seconds = retryAfterSeconds(error);
  if (seconds === null) return 'Try again in a moment.';
  return seconds < 90
    ? `Try again in ${seconds} s.`
    : `Try again in ${Math.ceil(seconds / 60)} min.`;
}

/** Explains `error`; `what` names what failed to load ("the users"), for the fallback detail. */
export function describeError(error: unknown, what?: string): ErrorDescription {
  const subject = what ? ` ${what}` : '';

  if (error instanceof ApiError) {
    const detail = backendMessage(error.body);
    switch (error.status) {
      case 400:
      case 422:
        return {
          title: 'Request refused',
          message: detail
            ? `The server refused the request: ${detail}`
            : 'The server refused the request. Check what you entered and try again.',
          retryable: false,
        };
      case 401:
        return {
          title: 'Signed out',
          message: 'Your session has ended. Sign in again to continue.',
          retryable: false,
        };
      case 403:
        return {
          title: 'Not allowed',
          message: "Your account's role does not allow this. Ask an administrator if you need it.",
          retryable: false,
        };
      case 404:
        return {
          title: 'Not found',
          message: `Could not find${subject || ' what you asked for'}. It may have been removed.`,
          retryable: false,
        };
      case 408:
      case 504:
        return {
          title: 'Timed out',
          message: 'The server took too long to answer. Try again in a moment.',
          retryable: true,
        };
      case 429:
        return {
          title: 'Too many requests',
          message: `You are going faster than the server allows. ${waitHint(error)}`,
          retryable: true,
        };
      case 502:
      case 503:
        return {
          title: 'Service unavailable',
          message: `The server is temporarily unavailable. ${waitHint(error)}`,
          retryable: true,
        };
    }
    if (error.status >= 500) {
      return {
        title: 'Server error',
        message: `The server ran into a problem${what ? ` loading${subject}` : ''}. Try again in a moment; if it keeps happening, tell an administrator.`,
        retryable: true,
      };
    }
    return {
      title: 'Request failed',
      message: detail ?? `The server answered with an unexpected status (${error.status}).`,
      retryable: false,
    };
  }

  if (isChunkLoadError(error)) {
    return {
      title: 'New version available',
      message: 'The app was updated since this page was opened. Reload to get the latest version.',
      retryable: true,
    };
  }
  if (isNetworkError(error)) {
    return {
      title: 'Connection problem',
      message: 'Could not reach the server. Check your connection and try again.',
      retryable: true,
    };
  }
  return {
    title: 'Something went wrong',
    message: `An unexpected error stopped${subject || ' this'} from loading. Try again; if it keeps happening, reload the page.`,
    retryable: true,
  };
}

/** `describeError(error, what).message`, for the places that show a single sentence. */
export function errorMessage(error: unknown, what?: string): string {
  return describeError(error, what).message;
}
