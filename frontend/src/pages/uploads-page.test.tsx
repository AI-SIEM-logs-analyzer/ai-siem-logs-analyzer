import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { callsTo, json, startTestSession, stubBackend } from '@/test/backend-stub';
import { stubXhr } from '@/test/fake-xhr';
import { renderRoute } from '@/test/render-route';

const analyst = () => json(200, { id: 2, username: 'anna', roles: ['ANALYST'] });
const emptyList = () => json(200, { items: [], page: 0, size: 20, total: 0 });

const pending = {
  id: 7,
  fileName: 'auth.log',
  fileSize: 2048,
  status: 'PENDING',
  detectedFormat: 'SYSLOG',
};

function logFile(name = 'auth.log') {
  return new File(['Jan  1 00:00:00 host sshd[1]: Accepted password'], name, {
    type: 'text/plain',
  });
}

describe('uploads page', () => {
  it('uploads a file with progress, then follows it until it is ingested', async () => {
    startTestSession();
    const statuses = [
      { ...pending, status: 'PROCESSING' },
      { ...pending, status: 'INGESTED', eventCount: 1234 },
    ];
    const fetchMock = stubBackend({
      'GET /api/auth/me': analyst,
      'GET /api/logs/uploads': emptyList,
      'GET /api/logs/uploads/7': () => json(200, statuses.shift() ?? statuses.at(-1)),
    });
    const { calls } = stubXhr(() => ({ status: 202, body: pending }));
    const user = userEvent.setup();

    renderRoute('/uploads');
    await user.upload(await screen.findByLabelText('Log file'), logFile());
    expect(screen.getByText('auth.log')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(await screen.findByRole('status')).toHaveTextContent('auth.log uploaded (2.0 KiB).');
    expect(calls).toHaveLength(1);
    expect(await screen.findByText('Parsing as SYSLOG…')).toBeInTheDocument();
    expect(
      await screen.findByText('Parsed as SYSLOG: 1,234 events indexed.', {}, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(callsTo(fetchMock, 'GET /api/logs/uploads/7').length).toBeGreaterThanOrEqual(2);

    await user.click(screen.getByRole('button', { name: 'Upload another file' }));
    expect(screen.getByRole('button', { name: 'Upload' })).toBeDisabled();
  });

  it('shows why parsing failed', async () => {
    startTestSession();
    stubBackend({
      'GET /api/auth/me': analyst,
      'GET /api/logs/uploads': emptyList,
      'GET /api/logs/uploads/7': () =>
        json(200, { ...pending, status: 'FAILED', errorMessage: 'unreadable line 3' }),
    });
    stubXhr(() => ({ status: 202, body: pending }));
    const user = userEvent.setup();

    renderRoute('/uploads');
    await user.upload(await screen.findByLabelText('Log file'), logFile());
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(await screen.findByText('Parsing failed.')).toBeInTheDocument();
    expect(screen.getByText('unreadable line 3')).toBeInTheDocument();
  });

  it('refuses a file the backend would not take, without sending it', async () => {
    startTestSession();
    stubBackend({ 'GET /api/auth/me': analyst, 'GET /api/logs/uploads': emptyList });
    const { calls } = stubXhr(() => ({ status: 202, body: pending }));
    const user = userEvent.setup({ applyAccept: false });

    renderRoute('/uploads');
    await user.upload(await screen.findByLabelText('Log file'), logFile('dump.gz'));

    expect(screen.getByRole('alert')).toHaveTextContent(/^Only \.log, \.txt/);
    expect(screen.getByRole('button', { name: 'Upload' })).toBeDisabled();
    expect(calls).toHaveLength(0);
  });

  it('says what the backend refused, and lets the user retry', async () => {
    startTestSession();
    stubBackend({ 'GET /api/auth/me': analyst, 'GET /api/logs/uploads': emptyList });
    const replies = [
      {
        status: 415,
        body: { error: 'unsupported_log_file', message: 'content looks binary' },
      },
      { status: 202, body: pending },
    ];
    stubXhr(() => replies.shift()!);
    const user = userEvent.setup();

    renderRoute('/uploads');
    await user.upload(await screen.findByLabelText('Log file'), logFile());
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'This does not look like a log file: content looks binary',
    );
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('status')).toHaveTextContent('auth.log uploaded');
  });

  it('cancels an upload in flight', async () => {
    startTestSession();
    stubBackend({ 'GET /api/auth/me': analyst, 'GET /api/logs/uploads': emptyList });
    const { instances } = stubXhr(() => 'hang');
    const user = userEvent.setup();

    renderRoute('/uploads');
    await user.upload(await screen.findByLabelText('Log file'), logFile());
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(await screen.findByRole('button', { name: /^Uploading…/ })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Upload cancelled.');
    expect(instances).toHaveLength(1);
  });

  it('lists uploads with their status', async () => {
    startTestSession();
    stubBackend({
      'GET /api/auth/me': () => json(200, { id: 3, username: 'vera', roles: ['VIEWER'] }),
      'GET /api/logs/uploads': () =>
        json(200, {
          items: [
            { ...pending, id: 9, fileName: 'web.log', status: 'INGESTED', eventCount: 42 },
            { ...pending, id: 8, fileName: 'bad.json', status: 'FAILED', errorMessage: 'boom' },
            { ...pending, id: 7, fileName: 'new.log', status: 'PENDING', uploadedBy: 'anna' },
          ],
          page: 0,
          size: 20,
          total: 3,
        }),
    });

    renderRoute('/uploads');

    const row = (name: string) => screen.getByText(name).closest('tr')!;
    expect(await screen.findByText('web.log')).toBeInTheDocument();
    expect(within(row('web.log')).getByText('Ingested')).toBeInTheDocument();
    expect(within(row('web.log')).getByText('42')).toBeInTheDocument();
    expect(within(row('bad.json')).getByText('Failed')).toBeInTheDocument();
    expect(within(row('bad.json')).getByText('boom')).toBeInTheDocument();
    expect(within(row('new.log')).getByText('Queued')).toBeInTheDocument();
    expect(within(row('new.log')).getByText(/by anna/)).toBeInTheDocument();
    // A viewer follows uploads but is not offered the form.
    expect(screen.queryByLabelText('Log file')).not.toBeInTheDocument();
  });
});
