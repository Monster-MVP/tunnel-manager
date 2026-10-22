import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contrastRatio, insideRoot, viewports } from '../../scripts/v2-ui-audit.mjs';

test('contrast evidence uses WCAG luminance for dark and light text', () => {
  assert.equal(contrastRatio([255, 255, 255], [0, 0, 0]), 21);
  assert.equal(contrastRatio([0, 0, 0], [255, 255, 255]), 21);
  assert.equal(contrastRatio([128, 128, 128], [128, 128, 128]), 1);
  assert.ok(contrastRatio([118, 118, 118], [255, 255, 255]) >= 4.5);
  assert.ok(contrastRatio([119, 119, 119], [255, 255, 255]) < 4.5);
});

test('evidence directory cannot escape the explicitly authorized project', () => {
  const root = '/Volumes/development/fixture-user/projects/tunnel-manager';
  assert.equal(insideRoot(root, 'var/reports/v2-ui/round2'), root + '/var/reports/v2-ui/round2');
  for (const value of ['../another-project', '/tmp/ui-audit', root, '.'])
    assert.throws(() => insideRoot(root, value));
});

test('required desktop sizes remain an explicit independent audit matrix', () => {
  assert.deepEqual(viewports, [{ width: 1440, height: 900 }, { width: 1280, height: 800 },
    { width: 1024, height: 768 }, { width: 768, height: 900 }]);
});
