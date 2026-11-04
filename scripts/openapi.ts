import { readFileSync, writeFileSync } from 'node:fs'
import { buildOpenApiSpec } from '../apps/iam-core/src/openapi/spec.js'
const file = new URL('../docs/openapi.json', import.meta.url)
const expected =
  JSON.stringify(
    buildOpenApiSpec(),
    (_key, value: unknown) =>
      value && typeof value === 'object' && !Array.isArray(value)
        ? Object.fromEntries(
            Object.entries(value).sort(([left], [right]) =>
              left.localeCompare(right),
            ),
          )
        : value,
    2,
  ) + '\n'
if (process.argv.includes('--write')) writeFileSync(file, expected)
else if (readFileSync(file, 'utf8') !== expected)
  throw new Error('OpenAPI drift: run npm run generate:openapi')
else console.log('Oathweave OpenAPI is current')
