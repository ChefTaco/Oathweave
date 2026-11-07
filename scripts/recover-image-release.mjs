// Validate an already-published image before retrying provenance/release metadata.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function verifyRecovery({ tag, digest, run, jobs, commit, index, images, repository }) {
  assert.match(tag, /^v\d+\.\d+\.\d+$/);
  assert.match(digest, /^sha256:[a-f0-9]{64}$/);
  assert.match(commit, /^[a-f0-9]{40}$/);
  assert.equal(run.repository.full_name, repository);
  assert.equal(run.path, '.github/workflows/release-image.yml');
  assert.equal(run.event, 'push');
  assert.equal(run.head_branch, tag);
  assert.equal(run.head_sha, commit);
  assert.equal(run.status, 'completed');
  for (const architecture of ['amd64', 'arm64']) {
    assert(jobs.some(job => job.name.startsWith(`build (${architecture},`) && job.conclusion === 'success'), 'Missing successful architecture build');
    const descriptor = index.manifests.find(item => item.platform?.os === 'linux' && item.platform.architecture === architecture);
    assert(descriptor, 'Missing image architecture');
    const labels = images[descriptor.digest]?.config?.Labels;
    assert.equal(labels?.['org.opencontainers.image.revision'], commit);
    assert.equal(labels?.['org.opencontainers.image.source'], `https://github.com/${repository}`);
    assert.equal(labels?.['org.opencontainers.image.version'], tag);
  }
  assert.equal(index.digest, digest, 'Published tag digest changed');
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const { RELEASE_TAG: tag, EXPECTED_DIGEST: digest, BUILD_RUN: buildRun, GITHUB_REPOSITORY: repository } = process.env;
  assert.match(tag ?? '', /^v\d+\.\d+\.\d+$/);
  assert.match(digest ?? '', /^sha256:[a-f0-9]{64}$/);
  assert.match(buildRun ?? '', /^[1-9]\d*$/);
  assert.equal(repository, 'ChefTaco/Oathweave');
  const gh = path => JSON.parse(execFileSync('gh', ['api', path], { encoding: 'utf8' }));
  const inspect = (reference, field) => JSON.parse(execFileSync('docker', ['buildx', 'imagetools', 'inspect', reference, '--format', `{{json .${field}}}`], { encoding: 'utf8' }));
  const commit = execFileSync('git', ['rev-parse', `${tag}^{commit}`], { encoding: 'utf8' }).trim();
  const image = 'ghcr.io/cheftaco/oathweave';
  const index = inspect(`${image}:${tag.slice(1)}`, 'Manifest');
  const images = Object.fromEntries(index.manifests.map(item => [item.digest, inspect(`${image}@${item.digest}`, 'Image')]));
  verifyRecovery({ tag, digest, repository, commit, index, images,
    run: gh(`repos/${repository}/actions/runs/${buildRun}`),
    jobs: gh(`repos/${repository}/actions/runs/${buildRun}/jobs?per_page=100`).jobs });
  appendFileSync(process.env.GITHUB_OUTPUT, `digest=${digest}\ntag=${tag}\n`);
  console.log('Verified original source, both architecture builds and the immutable image.');
}
