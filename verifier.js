/**
 * Charter attestation verifier — logic module.
 *
 * Runs unchanged in a browser (ES module) and in Node 20. It reads an EAS attestation on
 * Base (chain 8453) or Base Sepolia (84532), decodes the charter payload, fetches every text
 * from IPFS and recomputes the sha256 of the exact bytes so each text is shown as match or
 * mismatch.
 *
 * The payload schema is:
 *   "string version,string date,string[] names,bytes32[] digests,string[] cids"
 * names, digests and cids are parallel arrays, one entry per text.
 *
 * No bundler, no build step, one dependency-free ABI decoder: the schema is fixed, so a
 * hand-rolled reader is both smaller and easier to audit than pulling ethers into a static page.
 */

export const EAS_ADDRESS = '0x4200000000000000000000000000000000000021';

export const NETWORKS = {
  8453: { name: 'base', defaultRpc: 'https://mainnet.base.org', explorer: 'https://base.easscan.org' },
  84532: { name: 'base-sepolia', defaultRpc: 'https://sepolia.base.org', explorer: 'https://base-sepolia.easscan.org' },
};

/** getAttestation(bytes32) selector = keccak256("getAttestation(bytes32)")[:4] */
const GET_ATTESTATION_SELECTOR = '0xf17325e7';

const SCHEMA = 'string version,string date,string[] names,bytes32[] digests,string[] cids';

// ---------------------------------------------------------------------------
// hex helpers
// ---------------------------------------------------------------------------

const strip0x = (h) => (h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h);

export function toHex32(word) {
  return '0x' + strip0x(word).padStart(64, '0').slice(-64);
}

function readWord(bytes, offset) {
  if (offset + 32 > bytes.length) throw new Error('abi: read past end of data');
  let out = 0n;
  for (let i = 0; i < 32; i++) out = (out << 8n) | BigInt(bytes[offset + i]);
  return out;
}

function hexToBytes(hex) {
  const clean = strip0x(hex);
  if (clean.length % 2) throw new Error('abi: odd-length hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function readString(bytes, offset) {
  const len = Number(readWord(bytes, offset));
  if (offset + 32 + len > bytes.length) throw new Error('abi: string length past end of data');
  return new TextDecoder().decode(bytes.slice(offset + 32, offset + 32 + len));
}

/** Top-level offsets are absolute from the start of the encoded tuple. */
function readOffset(bytes, headOffset) {
  const abs = Number(readWord(bytes, headOffset));
  if (abs > bytes.length) throw new Error('abi: offset past end of data');
  return abs;
}

/** Offsets inside a dynamic array are relative to the word after the length. */
function readRelOffset(bytes, base, headOffset) {
  const abs = base + Number(readWord(bytes, headOffset));
  if (abs > bytes.length) throw new Error('abi: element offset past end of data');
  return abs;
}

/**
 * Decode the charter payload.
 * @param {string} dataHex ABI-encoded attestation `data`
 * @returns {{version:string,date:string,names:string[],digests:string[],cids:string[]}}
 */
export function decodeCharterData(dataHex) {
  const bytes = hexToBytes(dataHex);
  // head: 5 words (version, date, names, digests, cids), all dynamic -> all are offsets
  const version = readString(bytes, readOffset(bytes, 0));
  const date = readString(bytes, readOffset(bytes, 32));
  const names = readStringArray(bytes, readOffset(bytes, 64));
  const digests = readBytes32Array(bytes, readOffset(bytes, 96));
  const cids = readStringArray(bytes, readOffset(bytes, 128));
  if (names.length !== digests.length || names.length !== cids.length) {
    throw new Error(`abi: parallel array length mismatch (${names.length}/${digests.length}/${cids.length})`);
  }
  return { version, date, names, digests, cids };
}

function readStringArray(bytes, offset) {
  const count = Number(readWord(bytes, offset));
  const out = [];
  for (let i = 0; i < count; i++) out.push(readString(bytes, readRelOffset(bytes, offset + 32, offset + 32 + i * 32)));
  return out;
}

function readBytes32Array(bytes, offset) {
  const count = Number(readWord(bytes, offset));
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push('0x' + bytesToHex(bytes.slice(offset + 32 + i * 32, offset + 64 + i * 32)));
  }
  return out;
}

// ---------------------------------------------------------------------------
// sha256 that works in both runtimes
// ---------------------------------------------------------------------------

async function sha256Hex(bytes) {
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
  }
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(bytes).digest('hex');
}

// ---------------------------------------------------------------------------
// JSON-RPC + EAS
// ---------------------------------------------------------------------------

async function rpcCall(rpc, method, params, fetchImpl) {
  const res = await fetchImpl(rpc, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`rpc ${method}: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`rpc ${method}: ${body.error.message || JSON.stringify(body.error)}`);
  return body.result;
}

/**
 * Decode the fixed EAS Attestation struct returned by getAttestation.
 * Layout (10 fields, 9 static then one dynamic):
 *   0 uid, 1 schema, 2 time, 3 expirationTime, 4 revocationTime, 5 refUID,
 *   6 recipient, 7 attester, 8 revocable, 9 data (offset, relative to the tuple head)
 */
function decodeAttestation(ret) {
  const bytes = hexToBytes(ret);
  const word = (i) => '0x' + bytesToHex(bytes.slice(i * 32, (i + 1) * 32));
  const addrAt = (i) => '0x' + bytesToHex(bytes.slice(i * 32 + 12, (i + 1) * 32));
  const uid = word(0);
  const schema = word(1);
  const time = Number(readWord(bytes, 2 * 32));
  const revocationTime = Number(readWord(bytes, 4 * 32));
  const attester = addrAt(7);
  const revocable = readWord(bytes, 8 * 32) !== 0n;
  const dataOff = Number(readWord(bytes, 9 * 32));
  if (dataOff > bytes.length) throw new Error('abi: data offset past end');
  const len = Number(readWord(bytes, dataOff));
  if (dataOff + 32 + len > bytes.length) throw new Error('abi: data length past end');
  const data = '0x' + bytesToHex(bytes.slice(dataOff + 32, dataOff + 32 + len));
  return { uid, schema, time, revocationTime, attester, revocable, data };
}

// ---------------------------------------------------------------------------
// IPFS
// ---------------------------------------------------------------------------

async function fetchCidBytes(cid, ipfs, fetchImpl) {
  const base = (ipfs || 'https://ipfs.io/ipfs/').replace(/\/?$/, '/');
  const url = base + cid;
  const res = await fetchImpl(url, { headers: { accept: '*/*' } });
  if (!res.ok) throw new Error(`ipfs: HTTP ${res.status} for ${cid}`);
  return new Uint8Array(await res.arrayBuffer());
}

// ---------------------------------------------------------------------------
// main entry
// ---------------------------------------------------------------------------

/**
 * Verify a charter attestation end to end.
 * @param {{uid:string, network?:number, rpc?:string, ipfs?:string, fetchImpl?:Function}} opts
 */
export async function verifyCharter(opts = {}) {
  const { uid, network = 8453, ipfs, fetchImpl = globalThis.fetch } = opts;
  const net = NETWORKS[network];
  if (!net) throw new Error(`unsupported network ${network} (use 8453 or 84532)`);
  const rpc = opts.rpc || net.defaultRpc;

  const result = {
    ok: false,
    attestation: { uid: uid || null, attester: null, time: null, revoked: false },
    texts: [],
  };

  try {
    if (!uid || !/^0x[0-9a-fA-F]{64}$/.test(uid)) throw new Error('uid must be 0x + 64 hex characters');

    const ret = await rpcCall(rpc, 'eth_call', [{ to: EAS_ADDRESS, data: GET_ATTESTATION_SELECTOR + strip0x(uid) }, 'latest'], fetchImpl);
    if (!ret || strip0x(ret).length < 64) throw new Error('attestation not found');

    const att = decodeAttestation(ret);
    result.attestation = {
      uid: att.uid,
      attester: att.attester,
      time: att.time,
      revoked: att.revocationTime !== 0,
    };

    if (att.revocationTime !== 0) {
      result.reason = 'attestation is revoked';
      return result;
    }

    const decoded = decodeCharterData(att.data);

    for (let i = 0; i < decoded.names.length; i++) {
      const entry = { name: decoded.names[i], cid: decoded.cids[i], expected: decoded.digests[i], actual: null, match: false };
      try {
        const bytes = await fetchCidBytes(entry.cid, ipfs, fetchImpl);
        entry.actual = await sha256Hex(bytes);
        entry.match = strip0x(entry.actual).toLowerCase() === strip0x(entry.expected).toLowerCase();
      } catch (e) {
        entry.error = e.message || String(e);
      }
      result.texts.push(entry);
    }

    result.ok = result.texts.length > 0 && result.texts.every((t) => t.match);
    if (!result.ok && !result.reason) {
      const bad = result.texts.filter((t) => !t.match).map((t) => t.name);
      result.reason = bad.length ? `mismatch: ${bad.join(', ')}` : 'no texts found';
    }
  } catch (e) {
    result.reason = e.message || String(e);
  }
  return result;
}

export const CHARTER_SCHEMA = SCHEMA;
