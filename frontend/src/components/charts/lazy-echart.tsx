import { lazy } from 'react';

export const LazyEChart = lazy(() =>
  import('@/components/charts/echart').then((module) => ({ default: module.EChart })),
);
