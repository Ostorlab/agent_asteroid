/* Local-only vendor differential fixture. Setup is documented in
 * docs/dompurify-shadow-root-assessment.md. No expression is evaluated. */
'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const modules = path.resolve(process.argv[2]);
const { JSDOM } = require(path.join(modules, 'jsdom'));
const dialects = [['$', '{7*7}'], ['{', '{7*7}', '}'], ['<', '%= 7*7 %', '>']];
let checked = 0;

function fixture(document, shape, fragments) {
  const host = document.createElement('div');
  let content = host;
  if (shape !== 'light') content = host.attachShadow({ mode: 'open' });
  if (shape === 'nested') {
    const inner = document.createElement('section');
    content.appendChild(inner);
    content = inner.attachShadow({ mode: 'open' });
  }
  if (shape === 'template') {
    const template = document.createElement('template');
    content.appendChild(template);
    content = template.content;
  }
  for (const [index, fragment] of fragments.entries()) {
    if (index > 0) content.appendChild(document.createElement('object'));
    content.appendChild(document.createTextNode(fragment));
  }
  return { host, content };
}

for (const [packageName, version] of [
  ['dompurify-vulnerable', '3.4.16'],
  ['dompurify-patched', '3.4.17'],
]) {
  const window = new JSDOM('').window;
  const purify = require(path.join(modules, packageName))(window);
  assert.equal(purify.version, version);
  for (const shape of ['shadow', 'nested', 'template', 'light']) {
    for (const fragments of dialects) {
      const { host, content } = fixture(window.document, shape, fragments);
      purify.sanitize(host, { IN_PLACE: true, SAFE_FOR_TEMPLATES: true });
      assert.equal(content.querySelector('object'), null);
      const survives = content.textContent.includes(fragments.join(''));
      // The old final pass cannot enter a shadow root to find its templates either.
      const expected = version === '3.4.16' && shape !== 'light';
      assert.equal(survives, expected, `${version}: ${shape}: ${fragments.join('')}`);
      checked++;
    }
  }
  // Disabled template safety is a configuration issue, not evidence of this bypass.
  const control = fixture(window.document, 'shadow', dialects[0]);
  purify.sanitize(control.host, { IN_PLACE: true, SAFE_FOR_TEMPLATES: false });
  assert.equal(control.content.textContent, dialects[0].join(''));
  checked++;
  for (const mode of ['RETURN_DOM', 'RETURN_DOM_FRAGMENT']) {
    const { host } = fixture(window.document, 'shadow', dialects[0]);
    const result = purify.sanitize(host, { [mode]: true, SAFE_FOR_TEMPLATES: true });
    // jsdom 26 does not preserve these roots during importNode. A mode flag
    // alone must not establish that a root reaches the downstream evaluator.
    assert.equal(result.querySelector('div').shadowRoot, null);
    checked++;
  }
  window.close();
}
console.log(`${checked} local vendor differential/control checks passed; no evaluation or network.`);
