import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { ApiError, apiBaseUrl, unwrap } from '@/lib/api-client';
import { freshSession, refreshSession } from '@/lib/auth/auth-fetch';
import { backendMessage, errorMessage } from '@/lib/errors';
import type { Session } from '@/lib/auth/session';

// /api/logs: submitting a log file and following it through parsing.

export type LogUpload = components['schemas']['LogUploadResponse'];
export type LogUploadStatus = components['schemas']['LogUploadStatus'];
export type LogUploadPage = components['schemas']['PageResponseLogUploadResponse'];

/** Mirrors app.upload in the backend's application.yaml; the backend has the final say. */
export const UPLOAD_LIMITS = {
  maxFileSizeBytes: 50 * 1024 * 1024,
  extensions: ['log', 'txt', 'json', 'ndjson', 'csv'],
} as const;

/** How often an upload still being parsed is asked for again. */
export const UPLOAD_POLL_MS = 2_000;

export const uploadKeys = {
  all: ['uploads'] as const,
  list: (page: number, size: number) => ['uploads', 'list', { page, size }] as const,
  detail: (id: number) => ['uploads', 'detail', id] as const,
};

/** Whether the backend is done with an upload, one way or the other. */
export function isSettled(status: LogUploadStatus | undefined): boolean {
  return status === 'INGESTED' || status === 'FAILED';
}

/** Why a file cannot be uploaded, checked before sending it; null when it may go. */
export function checkFile(file: File): string | null {
  const extension = file.name.includes('.') ? file.name.split('.').pop()!.toLowerCase() : '';
  if (!(UPLOAD_LIMITS.extensions as readonly string[]).includes(extension)) {
    return `Only ${UPLOAD_LIMITS.extensions.map((e) => `.${e}`).join(', ')} files can be uploaded.`;
  }
  if (file.size === 0) return 'The file is empty.';
  if (file.size > UPLOAD_LIMITS.maxFileSizeBytes) {
    return `The file is ${formatBytes(file.size)}; the limit is ${formatBytes(UPLOAD_LIMITS.maxFileSizeBytes)}.`;
  }
  return null;
}

export interface UploadProgress {
  loaded: number;
  total: number;
}

export interface UploadOptions {
  onProgress?: (progress: UploadProgress) => void;
  signal?: AbortSignal;
}

/**
 * Sends `file` to POST /api/logs/upload and resolves to the metadata the backend recorded for it
 * (status PENDING: parsing happens afterwards, on the Kafka consumer).
 *
 * This is the one call that does not go through openapi-fetch: `fetch` cannot report how much of
 * a request body has been sent, and a 50 MiB file needs a progress bar. It keeps `authFetch`'s
 * contract by hand: the bearer of a fresh session, one renewal and replay on a 401. Rejects with
 * `ApiError` for a status outside 2xx, and with a `DOMException` named `AbortError` when
 * `signal` aborts.
 */
export async function uploadLogFile(file: File, options: UploadOptions = {}): Promise<LogUpload> {
  const session = await freshSession();
  try {
    return await send(file, session, options);
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 401 || !session) throw error;
    const renewed = await refreshSession(session);
    if (!renewed || renewed.accessToken === session.accessToken) throw error;
    return send(file, renewed, options);
  }
}

function send(
  file: File,
  session: Session | null,
  { onProgress, signal }: UploadOptions,
): Promise<LogUpload> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('Upload cancelled', 'AbortError'));
      return;
    }

    const xhr = new XMLHttpRequest();
    const abort = () => xhr.abort();
    signal?.addEventListener('abort', abort, { once: true });
    const done = () => signal?.removeEventListener('abort', abort);

    xhr.open('POST', `${apiBaseUrl}/api/logs/upload`);
    xhr.setRequestHeader('Accept', 'application/json');
    if (session) xhr.setRequestHeader('Authorization', `Bearer ${session.accessToken}`);
    xhr.upload.onprogress = (event) => {
      onProgress?.({
        loaded: event.loaded,
        total: event.lengthComputable ? event.total : file.size,
      });
    };
    xhr.onload = () => {
      done();
      const body = parseBody(xhr.responseText);
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as LogUpload);
        return;
      }
      reject(
        new ApiError(
          xhr.status,
          body,
          `/api/logs/upload failed with ${xhr.status}`,
          parseHeaders(xhr.getAllResponseHeaders()),
        ),
      );
    };
    xhr.onerror = () => {
      done();
      reject(new TypeError('Network error: the backend could not be reached.'));
    };
    xhr.onabort = () => {
      done();
      reject(new DOMException('Upload cancelled', 'AbortError'));
    };

    const form = new FormData();
    form.append('file', file, file.name);
    xhr.send(form);
  });
}

function parseBody(text: string): unknown {
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function parseHeaders(raw: string): Headers {
  const headers = new Headers();
  for (const line of raw.trim().split(/[\r\n]+/)) {
    const colon = line.indexOf(':');
    if (colon > 0) headers.append(line.slice(0, colon).trim(), line.slice(colon + 1).trim());
  }
  return headers;
}

/** What to tell the user about a failed upload request. */
export function uploadErrorMessage(error: Error): string {
  if (error instanceof DOMException && error.name === 'AbortError') return 'Upload cancelled.';
  if (!(error instanceof ApiError)) return `Upload failed. ${errorMessage(error)}`;
  const detail = backendMessage(error.body);
  switch (error.status) {
    case 400:
      return `The backend refused the file${detail ? `: ${detail}` : '.'}`;
    case 401:
      return 'Your session has ended. Sign in again to upload.';
    case 403:
      return 'Your account is not allowed to upload log files.';
    case 413: {
      const max = (error.body as { maxSizeBytes?: unknown } | undefined)?.maxSizeBytes;
      return typeof max === 'number'
        ? `The file is larger than the ${formatBytes(max)} limit.`
        : 'The file is larger than the upload limit.';
    }
    case 415:
      return `This does not look like a log file${detail ? `: ${detail}` : '.'}`;
    case 429: {
      const seconds = Number(error.headers.get('Retry-After'));
      const wait = seconds > 0 ? ` in ${seconds} s` : ' later';
      return `Too many uploads. Try again${wait}.`;
    }
    default:
      return `Upload failed. ${errorMessage(error)}`;
  }
}

export function fetchUpload(id: number): Promise<LogUpload> {
  return unwrap(api.GET('/api/logs/uploads/{id}', { params: { path: { id } } }));
}

/** One upload's metadata, asked for again every couple of seconds until it settles. */
export function useUpload(id: number | undefined) {
  return useQuery({
    queryKey: uploadKeys.detail(id ?? -1),
    queryFn: () => fetchUpload(id!),
    enabled: id !== undefined,
    staleTime: 0,
    refetchInterval: (query) => (isSettled(query.state.data?.status) ? false : UPLOAD_POLL_MS),
  });
}

export function fetchUploads(page: number, size: number): Promise<LogUploadPage> {
  return unwrap(api.GET('/api/logs/uploads', { params: { query: { page, size } } }));
}

/** A page of uploads, newest first, polled while any row on it is still being parsed. */
export function useUploads(page = 0, size = 20) {
  return useQuery({
    queryKey: uploadKeys.list(page, size),
    queryFn: () => fetchUploads(page, size),
    placeholderData: keepPreviousData,
    refetchInterval: (query) =>
      query.state.data?.items?.some((upload) => !isSettled(upload.status)) ? UPLOAD_POLL_MS : false,
  });
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 10 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}
