import { ApiError } from '@/lib/api-client';
import { callsTo, json, startTestSession, stubBackend, tokens } from '@/test/backend-stub';
import { stubXhr } from '@/test/fake-xhr';
import {
  checkFile,
  uploadErrorMessage,
  uploadLogFile,
  UPLOAD_LIMITS,
  type UploadProgress,
} from './uploads';

const accepted = { id: 7, fileName: 'auth.log', status: 'PENDING', fileSize: 12 };

function logFile(name = 'auth.log', content = 'Jan 1 sshd: x') {
  return new File([content], name, { type: 'text/plain' });
}

describe('checkFile', () => {
  it('accepts a log file the backend would take', () => {
    expect(checkFile(logFile())).toBeNull();
    expect(checkFile(logFile('EVENTS.NDJSON'))).toBeNull();
  });

  it('refuses another extension, an empty file and one over the limit', () => {
    expect(checkFile(logFile('dump.gz'))).toMatch(/^Only \.log, \.txt/);
    expect(checkFile(logFile('noextension'))).toMatch(/^Only/);
    expect(checkFile(logFile('empty.log', ''))).toBe('The file is empty.');

    const huge = logFile();
    Object.defineProperty(huge, 'size', { value: UPLOAD_LIMITS.maxFileSizeBytes + 1 });
    expect(checkFile(huge)).toBe('The file is 50 MiB; the limit is 50 MiB.');
  });
});

describe('uploadLogFile', () => {
  it('posts the file with the bearer and reports progress', async () => {
    startTestSession();
    const { calls } = stubXhr(() => ({ status: 202, body: accepted }));
    const onProgress = vi.fn<(progress: UploadProgress) => void>();

    await expect(uploadLogFile(logFile(), { onProgress })).resolves.toEqual(accepted);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('POST');
    expect(new URL(calls[0].url).pathname).toBe('/api/logs/upload');
    expect(calls[0]?.headers.Authorization).toBe('Bearer access-1');
    expect((calls[0]?.body as FormData).get('file')).toBeInstanceOf(File);
    expect(onProgress.mock.calls.map(([p]) => p)).toEqual([
      { loaded: 500, total: 1000 },
      { loaded: 1000, total: 1000 },
    ]);
  });

  it('renews the session on a 401 and sends the file again', async () => {
    startTestSession();
    const fetchMock = stubBackend({ 'POST /api/auth/refresh': () => json(200, tokens('2')) });
    const { calls } = stubXhr((call) =>
      call.headers.Authorization === 'Bearer access-2'
        ? { status: 202, body: accepted }
        : { status: 401, body: { error: 'token_revoked' } },
    );

    await expect(uploadLogFile(logFile())).resolves.toEqual(accepted);
    expect(calls).toHaveLength(2);
    expect(callsTo(fetchMock, 'POST /api/auth/refresh')).toHaveLength(1);
  });

  it('rejects with the status, body and headers of a refusal', async () => {
    startTestSession();
    stubXhr(() => ({
      status: 429,
      body: { error: 'too_many_uploads' },
      headers: { 'Retry-After': '42' },
    }));

    const error = await uploadLogFile(logFile()).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(429);
    expect((error as ApiError).headers.get('Retry-After')).toBe('42');
    expect(uploadErrorMessage(error as ApiError)).toBe('Too many uploads. Try again in 42 s.');
  });

  it('stops sending when cancelled', async () => {
    startTestSession();
    stubXhr(() => 'hang');
    const controller = new AbortController();

    const pending = uploadLogFile(logFile(), { signal: controller.signal });
    await Promise.resolve();
    controller.abort();

    const error = await pending.catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DOMException);
    expect(uploadErrorMessage(error as Error)).toBe('Upload cancelled.');
  });

  it('reports an unreachable backend', async () => {
    startTestSession();
    stubXhr(() => 'error');

    const error = await uploadLogFile(logFile()).catch((e: unknown) => e);
    expect(uploadErrorMessage(error as Error)).toBe(
      'Upload failed. Could not reach the server. Check your connection and try again.',
    );
  });
});

describe('uploadErrorMessage', () => {
  const refusal = (status: number, body?: unknown) => new ApiError(status, body, 'failed');

  it('explains each refusal the upload endpoint makes', () => {
    expect(uploadErrorMessage(refusal(413, { maxSizeBytes: 52428800 }))).toBe(
      'The file is larger than the 50 MiB limit.',
    );
    expect(
      uploadErrorMessage(refusal(415, { message: 'file content looks binary, not a log file' })),
    ).toBe('This does not look like a log file: file content looks binary, not a log file');
    expect(uploadErrorMessage(refusal(400, 'file part is required'))).toBe(
      'The backend refused the file: file part is required',
    );
    expect(uploadErrorMessage(refusal(403))).toBe(
      'Your account is not allowed to upload log files.',
    );
    expect(uploadErrorMessage(refusal(500))).toMatch(
      /^Upload failed\. The server ran into a problem/,
    );
  });
});
