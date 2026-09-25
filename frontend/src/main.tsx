import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { Providers } from '@/app/providers';
import { createQueryClient } from '@/app/query-client';
import { routes } from '@/app/routes';
import './index.css';

const root = document.getElementById('root');
if (!root) throw new Error('index.html is missing the #root element');

const queryClient = createQueryClient();
const router = createBrowserRouter(routes);

createRoot(root).render(
  <StrictMode>
    <Providers queryClient={queryClient}>
      <RouterProvider router={router} />
    </Providers>
  </StrictMode>,
);
