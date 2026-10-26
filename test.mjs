/**
 * Tests for verifier.js — no network. They build the ABI blobs the same way the EAS contract
 * returns them, then drive verifyCharter with a fake fetch so the whole path (rpc call →
 * struct decode → charter decode → ipfs fetch → sha256 compare) is exercised.
 *
 * Run: node --test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { decodeCharterData, verifyCharter, EAS_ADDRESS, toHex32 } from './verifier.js';

// --- minimal ABI encoder (only the shapes this schema needs) ----------------

const pad = (hex) => hex.padStart(64, '0');
const word = (n) => pad(BigInt(n).toString(16));
const encString = (s) => {
  const b = Buffer.from(s, 'utf8');
  return { head: null, body: word(b.length) + b.toString('hex').padEnd(Math.ceil(b.length / 32) * 64 || 0, '0') };
};

function encodeCharter({ version, date, names, digests, cids }) {
  const parts = [];
  // five dynamic heads -> five offsets
  const encodeDynamic = (hex) => {
    const body = hex;
    return { body, size: body.length / 2 };
  };
  const strHex = (s) => {
    const b = Buffer.from(s, 'utf8');
    const padded = b.toString('hex').padEnd(Math.ceil(b.length / 32) * 64, '0');
    return word(b.length) + padded;
  };
  const strArrayHex = (arr) => {
    let out = word(arr.length);
    const bodies = arr.map(strHex);
    let off = arr.length * 32;
    for (const b of bodies) { out += word(off); off += b.length / 2; }
    return out + bodies.join('');
  };
  const bytes32ArrayHex = (arr) => {
    let out = word(arr.length);
    for (const d of arr) out += d.replace(/^0x/, '').padStart(64, '0').toLowerCase();
    return out;
  };

  const bodies = [
    strHex(version),
    strHex(date),
    strArrayHex(names),
    bytes32ArrayHex(digests),
    strArrayHex(cids),
  ];
  let head = '';
  let off = 5 * 32;
  for (const b of bodies) { head += word(off); off += b.length / 2; }
  return '0x' + head + bodies.join('');
}

function encodeAttestation({ uid, schema, time, revocationTime, attester, data }) {
  const head = [
    uid.replace(/^0x/, '').padStart(64, '0'),
    schema.replace(/^0x/, '').padStart(64, '0'),
    word(time),
    word(0),
    word(revocationTime),
    '0'.repeat(64),
    pad(attester.replace(/^0x/, '')),
    pad(attester.replace(/^0x/, '')),
    word(1),
  ];
  const dataHex = data.replace(/^0x/, '');
  const dataLen = dataHex.length / 2;
  const offset = 10 * 32; // 10 head slots: 9 static + the data offset word itself
  const tail = word(dataLen) + dataHex.padEnd(Math.ceil(dataLen / 32) * 64, '0');
  return '0x' + head.join('') + word(offset) + tail;
}

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// --- fixtures ---------------------------------------------------------------

const texts = {
  charter: 'The Founding Charter. Text one.',
  constitution: 'The Constitution. Text two, longer than the first one.',
  soul: 'The Soul. Short.',
};
const cids = {
  charter: 'bafycharter',
  constitution: 'bafyconstitution',
  soul: 'bafysoul',
};
const entries = Object.keys(texts);

function fixture() {
  const names = entries;
  const digests = entries.map((k) => '0x' + sha256(Buffer.from(texts[k])));
  const data = encodeCharter({
    version: '1.0.0',
    date: '2026-01-01',
    names,
    digests,
    cids: entries.map((k) => cids[k]),
  });
  const attestation = encodeAttestation({
    uid: '0x' + 'ab'.repeat(32),
    schema: '0x' + 'cd'.repeat(32),
    time: 1767225600,
    revocationTime: 0,
    attester: '0x' + '11'.repeat(20),
    data,
  });
  return { data, attestation, digests };
}

// --- tests ------------------------------------------------------------------

test('decodeCharterData round-trips the schema', () => {
  const { data, digests } = fixture();
  const out = decodeCharterData(data);
  assert.equal(out.version, '1.0.0');
  assert.equal(out.date, '2026-01-01');
  assert.deepEqual(out.names, entries);
  assert.deepEqual(out.digests.map((d) => d.toLowerCase()), digests.map((d) => d.toLowerCase()));
  assert.deepEqual(out.cids, entries.map((k) => cids[k]));
});

test('decodeCharterData rejects mismatched parallel arrays', () => {
  const bad = encodeCharter({
    version: '1.0.0',
    date: '2026-01-01',
    names: ['charter'],
    digests: ['0x' + 'aa'.repeat(32), '0x' + 'bb'.repeat(32)],
    cids: ['bafyone'],
  });
  assert.throws(() => decodeCharterData(bad), /parallel array length mismatch/);
});

test('verifyCharter reports ok when every digest matches', async () => {
  const { attestation } = fixture();
  const fetchImpl = async (url) => {
    if (url.includes('getAttestation') || url.includes('rpc') || url.endsWith('/')) {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: attestation }), { status: 200 });
    }
    return new Response('nope', { status: 404 });
  };
  // route eth_call vs ipfs by inspecting the request body / url
  const routingFetch = async (url, init = {}) => {
    if (init.method === 'POST') {
      const body = JSON.parse(init.body);
      if (body.method === 'eth_call') {
        assert.equal(body.params[0].to, EAS_ADDRESS);
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: attestation }), { status: 200 });
      }
    }
    const cid = url.split('/').pop();
    const key = entries.find((k) => cids[k] === cid);
    if (!key) return new Response('missing', { status: 404 });
    return new Response(Buffer.from(texts[key]), { status: 200 });
  };

  const out = await verifyCharter({ uid: '0x' + 'ab'.repeat(32), network: 8453, fetchImpl: routingFetch });
  assert.equal(out.ok, true, out.reason);
  assert.equal(out.texts.length, 3);
  assert.ok(out.texts.every((t) => t.match));
  assert.equal(out.attestation.attester, '0x' + '11'.repeat(20));
  assert.equal(out.attestation.revoked, false);
});

test('verifyCharter reports a mismatch per text and fails the whole result', async () => {
  const { attestation } = fixture();
  const routingFetch = async (url, init = {}) => {
    if (init.method === 'POST') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: attestation }), { status: 200 });
    }
    const cid = url.split('/').pop();
    const key = entries.find((k) => cids[k] === cid);
    // tamper with the constitution
    const body = key === 'constitution' ? Buffer.from('tampered text') : Buffer.from(texts[key] || '');
    return new Response(body, { status: 200 });
  };
  const out = await verifyCharter({ uid: '0x' + 'ab'.repeat(32), fetchImpl: routingFetch });
  assert.equal(out.ok, false);
  const bad = out.texts.filter((t) => !t.match).map((t) => t.name);
  assert.deepEqual(bad, ['constitution']);
  assert.match(out.reason, /mismatch: constitution/);
});

test('verifyCharter surfaces a revoked attestation without fetching IPFS', async () => {
  const { data } = fixture();
  const attestation = encodeAttestation({
    uid: '0x' + 'ab'.repeat(32), schema: '0x' + 'cd'.repeat(32), time: 1767225600,
    revocationTime: 1767225700, attester: '0x' + '11'.repeat(20), data,
  });
  let ipfsTouched = false;
  const routingFetch = async (url, init = {}) => {
    if (init.method === 'POST') return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: attestation }), { status: 200 });
    ipfsTouched = true;
    return new Response('x', { status: 200 });
  };
  const out = await verifyCharter({ uid: '0x' + 'ab'.repeat(32), fetchImpl: routingFetch });
  assert.equal(out.ok, false);
  assert.equal(out.attestation.revoked, true);
  assert.match(out.reason, /revoked/);
  assert.equal(ipfsTouched, false);
});

test('verifyCharter validates the uid shape before any network call', async () => {
  let called = false;
  const out = await verifyCharter({ uid: '0xdeadbeef', fetchImpl: async () => { called = true; return new Response('{}'); } });
  assert.equal(out.ok, false);
  assert.match(out.reason, /uid must be/);
  assert.equal(called, false);
});
