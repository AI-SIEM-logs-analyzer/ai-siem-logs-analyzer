import { LoaderCircle, Sparkles } from 'lucide-react';
import { useSummarizeAlert, type Alert, type AttackType } from '@/api/alerts';
import { Can } from '@/components/auth/can';
import { SeverityBadge } from '@/components/events/severity-badge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ApiError } from '@/lib/api-client';
import { backendMessage, errorMessage } from '@/lib/errors';
import { formatEventTime } from '@/lib/event-fields';

const ATTACK_TYPE_LABELS: Record<AttackType, string> = {
  BRUTE_FORCE: 'Brute force',
  CREDENTIAL_STUFFING: 'Credential stuffing',
  SQL_INJECTION: 'SQL injection',
  PATH_TRAVERSAL: 'Path traversal',
  CROSS_SITE_SCRIPTING: 'Cross-site scripting',
  COMMAND_INJECTION: 'Command injection',
  REMOTE_CODE_EXECUTION: 'Remote code execution',
  RECONNAISSANCE: 'Reconnaissance',
  DENIAL_OF_SERVICE: 'Denial of service',
  PRIVILEGE_ESCALATION: 'Privilege escalation',
  DATA_EXFILTRATION: 'Data exfiltration',
  MALWARE: 'Malware',
  ANOMALOUS_BEHAVIOUR: 'Anomalous behaviour',
  BENIGN: 'Likely benign',
  OTHER: 'Other',
};

/** Why the summary could not be had; the backend's own sentence when the provider failed. */
function failure(error: unknown): string {
  if (error instanceof ApiError && error.status === 502) {
    return backendMessage(error.body) ?? 'The AI provider could not summarise this alert.';
  }
  return errorMessage(error);
}

/**
 * The model's reading of the alert, and, for whoever may triage, the button that asks for one.
 * The model's severity is shown beside the rule's, never in its place.
 */
export function AiSummaryCard({ id, alert }: { id: number; alert: Alert }) {
  const summarize = useSummarizeAlert(id);
  const summary = alert.aiSummary;

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="space-y-1.5">
          <CardTitle>
            <h2 className="flex items-center gap-2">
              <Sparkles aria-hidden className="size-4" />
              AI summary
            </h2>
          </CardTitle>
          <CardDescription>
            A language model&apos;s reading of this alert. Check it against the evidence before
            acting on it.
          </CardDescription>
        </div>
        <Can permission="alerts:summarize">
          <Button
            variant="outline"
            size="sm"
            disabled={summarize.isPending}
            onClick={() => summarize.mutate()}
          >
            {summarize.isPending ? (
              <LoaderCircle aria-hidden className="animate-spin" />
            ) : (
              <Sparkles aria-hidden />
            )}
            {summarize.isPending ? 'Summarising…' : summary ? 'Summarise again' : 'Summarise'}
          </Button>
        </Can>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {summarize.isError && (
          <p role="alert" className="text-destructive">
            {failure(summarize.error)}
          </p>
        )}
        {summary ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={summary.severity} />
              {summary.attackType && (
                <Badge variant="secondary">{ATTACK_TYPE_LABELS[summary.attackType]}</Badge>
              )}
            </div>
            <p className="wrap-anywhere whitespace-pre-wrap">{summary.summary}</p>
            <section className="space-y-1">
              <h3 className="font-medium">Recommended action</h3>
              <p className="wrap-anywhere whitespace-pre-wrap">{summary.recommendedAction}</p>
            </section>
            {summary.evidence && summary.evidence.length > 0 && (
              <section className="space-y-1">
                <h3 className="font-medium">Evidence</h3>
                <p className="text-muted-foreground text-xs">
                  Values the model quoted from this alert; each was checked to be in it.
                </p>
                <ul aria-label="Evidence" className="flex flex-wrap gap-1.5">
                  {summary.evidence.map((value) => (
                    <li key={value}>
                      <code className="bg-muted wrap-anywhere rounded px-1.5 py-0.5 font-mono text-xs">
                        {value}
                      </code>
                    </li>
                  ))}
                </ul>
              </section>
            )}
            <p className="text-muted-foreground text-xs">
              By {summary.model ?? 'an unknown model'}
              {summary.summarizedAt && (
                <>
                  {' · '}
                  <time dateTime={summary.summarizedAt}>
                    {formatEventTime(summary.summarizedAt)}
                  </time>
                </>
              )}
            </p>
          </>
        ) : (
          !summarize.isPending && (
            <p className="text-muted-foreground">No model has summarised this alert yet.</p>
          )
        )}
      </CardContent>
    </Card>
  );
}
