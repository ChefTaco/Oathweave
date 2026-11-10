// Compile seed imports with their normal source roots, then retain only the
// three seed entry modules and point them at the primary compiled database code.
import { mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const staging = fileURLToPath(new URL('../dist/.seed-build/', import.meta.url));
const destination = fileURLToPath(new URL('../dist/prisma/', import.meta.url));
mkdirSync(destination, { recursive: true });
for (const name of ['seed', 'seed-client-secret', 'suite-bootstrap']) {
  let source = readFileSync(`${staging}prisma/${name}.js`, 'utf8');
  if (name === 'seed') {
    for (const module of ['generated', 'prisma-sqlite']) {
      const from = `from '../src/db/${module}/index.js'`;
      const to = `from '../db/${module}/index.js'`;
      if (source.split(from).length - 1 !== 1) throw new Error(`Compiled seed import differs: ${module}`);
      source = source.replace(from, to);
    }
  }
  writeFileSync(`${destination}${name}.js`, source);
}
rmSync(staging, { recursive: true });
