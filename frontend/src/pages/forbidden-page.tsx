import { Link } from 'react-router';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';

export function ForbiddenPage() {
  return (
    <>
      <PageHeader
        title="Access denied"
        description="Your account's role does not allow this page. Ask an administrator if you need it."
      />
      <div>
        <Button asChild variant="outline">
          <Link to="/">Back to the dashboard</Link>
        </Button>
      </div>
    </>
  );
}
