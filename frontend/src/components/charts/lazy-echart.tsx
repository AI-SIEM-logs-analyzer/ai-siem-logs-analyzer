import { lazy } from 'react';

// ECharts is about half of the bundle; it loads with the first chart rather than with the app.
// Render it inside <Suspense>.
export const LazyEChart = lazy(() =>
  import('@/components/charts/echart').then((module) => ({ default: module.EChart })),
);
