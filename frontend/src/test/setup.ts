import '@testing-library/jest-dom/vitest';
import { reloadSession } from '@/lib/auth/session';

afterEach(() => {
  vi.unstubAllGlobals();

  localStorage.clear();
  reloadSession();
});
