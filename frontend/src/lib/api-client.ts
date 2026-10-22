import createClient from 'openapi-fetch';
import type { paths } from '@/api/schema';

export const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || window.location.origin).replace(
  /\/+$/,
  '',
);

export type ApiClient = ReturnType<typeof createClient<paths>>;

export function createApiClient(
  fetchImpl: (request: Request) => Promise<Response> = (request) => globalThis.fetch(request),
): ApiClient {
  return createClient<paths>({ baseUrl: apiBaseUrl, fetch: fetchImpl });
}

export const publicApi = createApiClient();

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
  acceptStatuses?: readonly number[];
}

export async function unwrap<T>(
  pending: Promise<ApiResult<T>>,
  { acceptStatuses = [] }: UnwrapOptions = {},
): Promise<T> {
  const { data, error, response } = await pending;
  if (response.ok) return data as T;

  if (acceptStatuses.includes(response.status)) return error as T;

  const where = response.url ? new URL(response.url).pathname : 'request';
  throw new ApiError(
    response.status,
    error,
    `${where} failed with ${response.status}`,
    response.headers,
  );
}
