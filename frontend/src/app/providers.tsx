import { QueryClientProvider, type QueryClient } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { useEffect, type ReactNode } from 'react';
import { getSession, subscribeSession } from '@/lib/auth/session';

interface ProvidersProps {
  queryClient: QueryClient;
  children: ReactNode;
}

export function Providers({ queryClient, children }: ProvidersProps) {
  useEffect(
    () =>
      subscribeSession(() => {
        if (!getSession()) queryClient.clear();
      }),
    [queryClient],
  );

  return (
    <QueryClientProvider client={queryClient}>
      {children}

      <ReactQueryDevtools buttonPosition="bottom-left" />
    </QueryClientProvider>
  );
}
