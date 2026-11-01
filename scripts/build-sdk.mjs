import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));

// Use the checked-in lockfile's compiler tools. Never fetch a compiler implicitly.
for (const [name, expected] of Object.entries({ tsup: '8.5.1', esbuild: '0.28.2', typescript: '5.9.3' })) {
  const installed = JSON.parse(await readFile(require.resolve(`${name}/package.json`), 'utf8'));
  if (installed.version !== expected) {
    throw new Error(`The SDK build requires ${name}@${expected}; run npm ci in the repository root.`);
  }
}

const { build } = await import('tsup');
process.chdir(root);
await build({
  entry: {
    index: 'src/sdk.ts',
    core: 'src/sdk-core.ts',
    express: 'src/http.ts',
    oauth: 'src/sdk-oauth.ts',
    'workos-connect': 'src/workos-connect.ts',
    'workos-connect-express': 'src/workos-connect-express.ts',
    'workos-connect-postgres': 'src/workos-connect-postgres.ts',
  },
  format: ['esm', 'cjs'],
  platform: 'node',
  target: 'node22',
  outDir: join(root, 'dist'),
  clean: true,
  dts: true,
  splitting: true,
  sourcemap: false,
  minify: false,
  external: Object.keys(manifest.dependencies),
  config: false,
});
