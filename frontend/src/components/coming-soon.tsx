import type { LucideIcon } from 'lucide-react';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

interface ComingSoonProps {
  icon: LucideIcon;
  title: string;
  description: string;
}

/** Stands in for a page whose feature has a route but no screen yet. */
export function ComingSoon({ icon: Icon, title, description }: ComingSoonProps) {
  return (
    <Card className="border-dashed">
      <CardHeader className="items-center text-center">
        <Icon className="text-muted-foreground mx-auto size-8" aria-hidden />
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
    </Card>
  );
}
