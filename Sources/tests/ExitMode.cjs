'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

async function test() {
  const client = path.join(__dirname, '../client');
  const ids = new Map();
  const element = () => ({
    dataset: {}, options: [{}, {}], value: '', classList: { toggle() {} },
    append() {}, replaceChildren() {}, setAttribute() {},
    addEventListener(name, fn) { this['on' + name] = fn; }
  });
  for (const [, id] of fs.readFileSync(path.join(client, 'index.html'), 'utf8').matchAll(/\bid="([^"]+)"/g)) {
    ids.set(id, element());
  }
  const get = id => ids.get(id);
  const doc = { getElementById: get, querySelectorAll: () => [], body: element(), createElement: element, createElementNS: element };
  const state = { gateway: '192.0.2.1', mode: 'lan-gateway', ready: true };
  const calls = [];
  let emit;
  const api = {
    state: async () => state, onState: callback => { emit = callback; },
    async action(name, params) { calls.push([name, params]); return state; }
  };
  const script = fs.readFileSync(path.join(client, 'renderer.cjs'), 'utf8');
  vm.runInNewContext(script, { document: doc, window: { gateway: api }, Date, setTimeout, clearTimeout,
    AICompat: require(path.join(client, 'compatibility.cjs')) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(get('exit-mode').value, 'lan');
  assert.equal(get('exit-mode').options[1].disabled, true);
  emit({ ...state, tailscale_supported: true });
  get('exit-mode').value = 'tailscale';
  get('exit-mode').onchange();
  assert.equal(get('gateway-input').value, '');
  get('gateway-input').value = '100.80.11.12';
  get('gateway-form').onsubmit({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls[0][1].gateway, 'tailscale:100.80.11.12');
  const validated = { phase: 'validated', gateway: calls[0][1].gateway, exit: { ip: '203.0.113.8' },
    token: 'verified-token', expires_utc: new Date(Date.now() + 60000).toISOString() };
  emit({ ...state, tailscale_supported: true, gateway_operation: validated });
  assert.equal(get('apply').disabled, false);
  get('apply').onclick();
  assert.equal(calls[1][1].token, 'verified-token');
  await new Promise(resolve => setImmediate(resolve));
  get('exit-mode').value = 'lan';
  get('exit-mode').onchange();
  assert.equal(get('gateway-input').value, state.gateway);
  get('gateway-input').value = '100.80.11.12';
  emit({ ...state, tailscale_supported: true, gateway_operation: validated });
  assert.equal(get('apply').disabled, true, 'LAN must not reuse a Tailscale token for the same IP');
  console.log('PASS exit mode, legacy backend, candidate request, apply token and mode switch.');
}
test().catch(error => { console.error(error); process.exitCode = 1; });

