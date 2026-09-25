// Flat config (ESLint 9). typescript-eslint runs type-aware: every .ts/.tsx file belongs to
// one of the two tsconfigs below, and the typed rules read that program.
import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';
import prettierConfig from 'eslint-config-prettier';

export default tseslint.config(
  // src/api/schema.d.ts is openapi-typescript output: regenerated, never edited, so not linted.
  { ignores: ['dist', 'coverage', 'node_modules', 'src/api/schema.d.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.es2022 },
      parserOptions: {
        project: ['./tsconfig.json', './tsconfig.node.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Underscore marks a binding that exists to satisfy a signature and is not read.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    extends: [reactHooks.configs.flat['recommended-latest'], reactRefresh.configs.vite],
  },
  // shadcn/ui files export their cva variants next to the component. They are vendored
  // as generated, so they keep that shape rather than being split for Fast Refresh.
  {
    files: ['src/components/ui/**'],
    rules: { 'react-refresh/only-export-components': 'off' },
  },
  // Plain JavaScript (this file) sits in no tsconfig, so it gets no type information.
  {
    files: ['**/*.js'],
    extends: [tseslint.configs.disableTypeChecked],
  },
  // Disables every ESLint rule that would disagree with Prettier. Must stay last.
  prettierConfig,
);
