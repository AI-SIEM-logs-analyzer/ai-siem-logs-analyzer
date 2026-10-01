/** What a fake XHR answers: the response, or 'error' for a network failure. */
export interface XhrReply {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}

/** The requests a FakeXhr received, in order. */
export interface XhrCall {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Document | XMLHttpRequestBodyInit | null | undefined;
}

type Responder = (call: XhrCall, xhr: FakeXhr) => XhrReply | 'error' | 'hang';

/**
 * Replaces `XMLHttpRequest`, which jsdom would send over the network, with one answered by
 * `respond`. Each send reports upload progress at half and all of `progressTotal` bytes first.
 */
export function stubXhr(respond: Responder, progressTotal = 1000) {
  const calls: XhrCall[] = [];
  const instances: FakeXhr[] = [];

  class Stub extends FakeXhr {
    constructor() {
      super(respond, calls, progressTotal);
      instances.push(this);
    }
  }
  vi.stubGlobal('XMLHttpRequest', Stub);
  return { calls, instances };
}

export class FakeXhr {
  status = 0;
  responseText = '';
  upload: { onprogress: ((event: ProgressEvent) => void) | null } = { onprogress: null };
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onabort: (() => void) | null = null;

  private method = '';
  private url = '';
  private requestHeaders: Record<string, string> = {};
  private responseHeaders: Record<string, string> = {};
  private finished = false;

  constructor(
    private readonly respond: Responder,
    private readonly calls: XhrCall[],
    private readonly progressTotal: number,
  ) {}

  open(method: string, url: string) {
    this.method = method;
    this.url = url;
  }

  setRequestHeader(name: string, value: string) {
    this.requestHeaders[name] = value;
  }

  getAllResponseHeaders() {
    return Object.entries(this.responseHeaders)
      .map(([name, value]) => `${name}: ${value}\r\n`)
      .join('');
  }

  send(body?: Document | XMLHttpRequestBodyInit | null) {
    const call = { method: this.method, url: this.url, headers: this.requestHeaders, body };
    this.calls.push(call);
    const reply = this.respond(call, this);
    if (reply === 'hang') return;

    // Asynchronous, as a real request is.
    queueMicrotask(() => {
      if (this.finished) return;
      for (const loaded of [this.progressTotal / 2, this.progressTotal]) {
        this.upload.onprogress?.({
          loaded,
          total: this.progressTotal,
          lengthComputable: true,
        } as ProgressEvent);
      }
      this.finished = true;
      if (reply === 'error') {
        this.onerror?.();
        return;
      }
      this.status = reply.status;
      this.responseHeaders = { 'Content-Type': 'application/json', ...reply.headers };
      this.responseText = reply.body === undefined ? '' : JSON.stringify(reply.body);
      this.onload?.();
    });
  }

  abort() {
    if (this.finished) return;
    this.finished = true;
    this.onabort?.();
  }
}
