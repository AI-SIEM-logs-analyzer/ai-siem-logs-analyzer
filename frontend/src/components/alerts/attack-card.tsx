import { ExternalLink } from 'lucide-react';
import type { AlertTechnique } from '@/api/attack';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

function provenance(techniques: readonly AlertTechnique[]): string {
  if (techniques.length === 0) return 'No technique is mapped to this alert.';
  if (techniques.some((technique) => technique.source === 'AI')) {
    return 'Derived from the AI classification; no rule fired.';
  }
  return 'The techniques the rule that fired is mapped to.';
}

export function AttackCard({ techniques }: { techniques: readonly AlertTechnique[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>MITRE ATT&amp;CK</h2>
        </CardTitle>
        <CardDescription>{provenance(techniques)}</CardDescription>
      </CardHeader>
      {techniques.length > 0 && (
        <CardContent>
          <ul className="space-y-3">
            {techniques.map((technique) => (
              <li key={technique.id} className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-medium">{technique.id}</span>
                  {technique.url ? (
                    <a
                      href={technique.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 hover:underline"
                    >
                      {technique.name ?? technique.id}
                      <ExternalLink aria-hidden className="size-3" />
                    </a>
                  ) : (
                    <span className="text-muted-foreground">
                      {technique.name ?? 'Not in the loaded ATT&CK dataset'}
                    </span>
                  )}
                  {technique.source === 'AI' && <Badge variant="secondary">AI</Badge>}
                </div>
                {technique.tactics && technique.tactics.length > 0 && (
                  <p className="text-muted-foreground text-xs">
                    {technique.tactics.map((tactic) => tactic.name ?? tactic.id).join(' · ')}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </CardContent>
      )}
    </Card>
  );
}
