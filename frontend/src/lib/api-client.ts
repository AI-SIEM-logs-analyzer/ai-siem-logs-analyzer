// Thin fetch wrapper every backend call goes through. It stays hand-written until the client
// generated from the Quarkus OpenAPI spec replaces the per-endpoint types in src/api/.

const baseUrl = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '');

/** A response outside 2xx. `body` is the parsed JSON payload, or the raw text if it was not JSON. */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

export interface ApiRequestInit extends RequestInit {
  /** Statuses outside 2xx whose body is still a valid answer, e.g. 503 from a health check. */
  acceptStatuses?: readonly number[];
}

export function apiUrl(path: string): string {
  return `${baseUrl}${path}`;
}

export async function apiFetch<T>(path: string, init: ApiRequestInit = {}): Promise<T> {
  const { acceptStatuses = [], ...requestInit } = init;
  const headers = new Headers(requestInit.headers);
  if (!headers.has('Accept')) headers.set('Accept', 'application/json');

  const response = await fetch(apiUrl(path), { ...requestInit, headers });
  const body = await readBody(response);

  if (!response.ok && !acceptStatuses.includes(response.status)) {
    const method = requestInit.method ?? 'GET';
    throw new ApiError(response.status, body, `${method} ${path} failed with ${response.status}`);
  }
  return body as T;
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text === '') return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}
