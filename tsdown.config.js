import {defineConfig} from 'tsdown';

export default defineConfig({
  clean: true,
  dts: true,
  entry: [
    'src/index.ts',
    'src/client.ts',
  ],
  format: 'esm',
  minify: {
    mangle: false,
  },
  outDir: 'lib',
  sourcemap: false,
  target: 'es2022',
  unbundle: true,
});
