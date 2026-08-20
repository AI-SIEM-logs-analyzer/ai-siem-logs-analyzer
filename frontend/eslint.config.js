// Flat config (ESLint 9). Rules only — no React/Vite plugins yet, those arrive with the
// application scaffolding. Type-aware linting is deliberately off: there is no tsconfig.json
// to point a program at until the Vite scaffold lands.
import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import prettierConfig from 'eslint-config-prettier';

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'node_modules'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.es2022 },
    },
    rules: {
      // Underscore marks a binding that exists to satisfy a signature and is not read.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  // Disables every ESLint rule that would disagree with Prettier. Must stay last.
  prettierConfig,
);
