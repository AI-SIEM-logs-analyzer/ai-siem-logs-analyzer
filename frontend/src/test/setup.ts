import '@testing-library/jest-dom/vitest';
import { reloadSession } from '@/lib/auth/session';

afterEach(() => {
  vi.unstubAllGlobals();
  // Every test starts signed out; the session module re-reads the now empty storage.
  localStorage.clear();
  reloadSession();
});
