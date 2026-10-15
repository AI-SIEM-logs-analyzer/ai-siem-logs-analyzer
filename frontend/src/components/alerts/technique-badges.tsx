import type { AlertTechnique } from '@/api/attack';
import { Badge } from '@/components/ui/badge';

/**
 * One badge per ATT&CK technique: the ID on the badge, the name in its tooltip. A technique that
 * comes from the model's attack type rather than a rule is marked "AI", since no rule vouches for
 * it.
 */
export function TechniqueBadges({ techniques }: { techniques: readonly AlertTechnique[] }) {
  if (techniques.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {techniques.map((technique) => (
        <Badge
          key={technique.id}
          variant={technique.source === 'AI' ? 'secondary' : 'outline'}
          title={technique.name ? `${technique.id} ${technique.name}` : technique.id}
        >
          {technique.source === 'AI' && <span>AI</span>}
          <span className="font-mono">{technique.id}</span>
        </Badge>
      ))}
    </div>
  );
}
