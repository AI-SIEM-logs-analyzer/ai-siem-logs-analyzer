import createClient from 'openapi-fetch';
import type { paths } from '@/api/schema';

// The typed client every backend call goes through. `paths` is generated from the Quarkus
// OpenAPI spec (openapi/openapi.json → src/api/schema.d.ts, `pnpm api:generate`), so a path,
// a parameter or a body that the backend does not declare is a compile error here.

/**
 * Where the API lives. Unset means same origin, which is what the dev proxy expects. The
 * origin is spelled out rather than left empty because openapi-fetch builds a `Request`, and a
 * `Request` needs an absolute URL outside a browser (under Vitest, for one).
 */
export const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || window.location.origin).replace(
  /\/+$/,
  '',
);

export type ApiClient = ReturnType<typeof createClient<paths>>;

/**
 * A client bound to a fetch implementation. The global `fetch` is looked up per call rather
 * than captured, so a test that stubs it after this module loaded is still the one answering.
 */
export function createApiClient(
  fetchImpl: (request: Request) => Promise<Response> = (request) => globalThis.fetch(request),
): ApiClient {
  return createClient<paths>({ baseUrl: apiBaseUrl, fetch: fetchImpl });
}

/**
 * The client for calls that must not carry, or refresh, a session: sign-in, token refresh and
 * sign-out. Everything else uses `api` from `@/api/client`.
 */
export const publicApi = createApiClient();

/** A response outside 2xx. `body` is the parsed JSON payload, or the raw text if it was not JSON. */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly headers: Headers;

  constructor(status: number, body: unknown, message: string, headers = new Headers()) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    this.headers = headers;
  }
}

interface ApiResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

export interface UnwrapOptions {
  /** Statuses outside 2xx whose body is still a valid answer, e.g. 503 from a health check. */
  acceptStatuses?: readonly number[];
}

/**
 * The body of a typed call, or an `ApiError` for a status outside 2xx. openapi-fetch returns
 * `{ data, error }` instead of throwing; TanStack Query wants a rejection, and the query client
 * reads `ApiError.status` to decide whether a retry could help.
 */
export async function unwrap<T>(
  pending: Promise<ApiResult<T>>,
  { acceptStatuses = [] }: UnwrapOptions = {},
): Promise<T> {
  const { data, error, response } = await pending;
  if (response.ok) return data as T;
  // The spec declares the same schema for these statuses; openapi-fetch just files it as error.
  if (acceptStatuses.includes(response.status)) return error as T;

  const where = response.url ? new URL(response.url).pathname : 'request';
  throw new ApiError(
    response.status,
    error,
    `${where} failed with ${response.status}`,
    response.headers,
  );
}
