import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyRecovery } from './recover-image-release.mjs';
const fixture = () => {
  const commit = 'a'.repeat(40), digest = `sha256:${'b'.repeat(64)}`, tag = 'v2.0.4', repository = 'ChefTaco/Oathweave';
  const manifests = ['amd64', 'arm64'].map((architecture, i) => ({ digest: `sha256:${String(i).repeat(64)}`, platform: { os: 'linux', architecture } }));
  return { commit, digest, tag, repository,
    run: { repository: { full_name: repository }, path: '.github/workflows/release-image.yml', event: 'push', head_branch: tag, head_sha: commit, status: 'completed' },
    jobs: ['amd64', 'arm64'].map(arch => ({ name: `build (${arch}, runner)`, conclusion: 'success' })),
    index: { digest, manifests }, images: Object.fromEntries(manifests.map(item => [item.digest, { config: { Labels: { 'org.opencontainers.image.revision': commit, 'org.opencontainers.image.source': `https://github.com/${repository}`, 'org.opencontainers.image.version': tag } } }])) };
};
test('recovery accepts verified immutable image metadata', () => verifyRecovery(fixture()));
test('recovery rejects changed digests, source, builds, architectures and unsafe tag input', () => {
  for (const mutate of [v => { v.index.digest += '0'; }, v => { v.run.head_sha = 'c'.repeat(40); }, v => { v.jobs[0].conclusion = 'failure'; }, v => { v.index.manifests.pop(); }, v => { Object.values(v.images)[0].config.Labels['org.opencontainers.image.revision'] = 'c'.repeat(40); }, v => { v.tag = 'v2.0.4; echo invalid'; }]) {
    const value = fixture(); mutate(value); assert.throws(() => verifyRecovery(value));
  }
});
