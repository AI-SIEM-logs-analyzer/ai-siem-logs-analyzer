import { useMutation } from '@tanstack/react-query';
import { Shield } from 'lucide-react';
import type { FormEvent } from 'react';
import { Navigate, useSearchParams } from 'react-router';
import { signIn } from '@/api/auth';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { ApiError } from '@/lib/api-client';
import { useSession } from '@/lib/auth/use-session';

export function LoginPage() {
  const session = useSession();
  const [params] = useSearchParams();
  const target = safeRedirect(params.get('redirect'));
  const login = useMutation({ mutationFn: signIn });

  // Signing in starts a session, and a session is what sends the user on.
  if (session) return <Navigate to={target} replace />;

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const field = (name: string) => {
      const value = form.get(name);
      return typeof value === 'string' ? value : '';
    };
    login.mutate({ username: field('username'), password: field('password') });
  }

  return (
    <div className="flex min-h-svh items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Shield className="size-5" aria-hidden />
            <h1>Sign in to SIEM Analyzer</h1>
          </CardTitle>
          <CardDescription>
            {params.get('expired')
              ? 'Your session has expired. Sign in again to continue.'
              : 'Use the account your administrator gave you.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="flex flex-col gap-4" onSubmit={onSubmit}>
            <label className="flex flex-col gap-1.5 text-sm font-medium">
              Username
              <Input name="username" autoComplete="username" required autoFocus />
            </label>
            <label className="flex flex-col gap-1.5 text-sm font-medium">
              Password
              <Input name="password" type="password" autoComplete="current-password" required />
            </label>
            {login.error && (
              <p role="alert" className="text-destructive text-sm">
                {signInErrorMessage(login.error)}
              </p>
            )}
            <Button type="submit" disabled={login.isPending}>
              {login.isPending ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

function signInErrorMessage(error: Error): string {
  if (!(error instanceof ApiError)) return `Sign-in failed: ${error.message}`;
  if (error.status === 401) return 'Invalid username or password.';
  if (error.status === 429) {
    const seconds = Number(error.headers.get('Retry-After'));
    const wait = seconds > 0 ? ` in ${Math.ceil(seconds / 60)} min` : ' later';
    return `Too many sign-in attempts. Try again${wait}.`;
  }
  return `Sign-in failed: ${error.message}`;
}

/**
 * Where to go after signing in. Only a path on this origin is honoured: `?redirect=` comes from
 * the URL, and following an absolute or protocol-relative one would make this page an open
 * redirect.
 */
function safeRedirect(value: string | null): string {
  return value?.startsWith('/') && !value.startsWith('//') && !value.startsWith('/\\')
    ? value
    : '/';
}
