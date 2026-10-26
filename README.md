# Charter attestation verifier

Static page + ES module that proves a Founding Charter attested on chain matches its
published texts. Give it an EAS attestation UID on Base (8453) or Base Sepolia (84532):
it reads the attestation from the EAS contract, fetches every text from IPFS, recomputes
the sha256 of the exact bytes and reports match or mismatch per text.

No backend, no build step, no runtime dependencies.

## Files

| File | What it is |
|---|---|
| `index.html` | the static page (`index.html` at the repository root, as the brief requires) |
| `verifier.js` | ES module with all the logic — runs in the browser **and** in Node 20 |
| `test.mjs` | six tests, no network: ABI round-trip, parallel-array guard, match, mismatch, revoked, uid validation |

## Interface

```js
import { decodeCharterData, verifyCharter } from './verifier.js';

decodeCharterData(dataHex)
// -> { version, date, names[], digests[] (0x + 64 lowercase hex), cids[] }

await verifyCharter({ uid, network, rpc, ipfs })
// -> { ok, reason?, attestation: { uid, attester, time, revoked },
//      texts: [{ name, cid, expected, actual, match, error? }] }
```

`network` defaults to `8453`. `rpc` defaults to the network's public endpoint; `ipfs`
defaults to `https://ipfs.io/ipfs/`. Both are injectable so the module can be tested and
pointed at another gateway.

## Schema

```
string version,string date,string[] names,bytes32[] digests,string[] cids
```

`names`, `digests` and `cids` are parallel arrays with one entry per text (charter,
constitution, soul). Each digest is the sha256 of the exact bytes stored under its CID.

EAS: `0x4200000000000000000000000000000000000021`, `getAttestation(bytes32)`.

## Run the tests

```bash
node --test
```

All six pass with no network access. They build the ABI blobs the way the EAS struct is
returned and drive `verifyCharter` with a fake `fetch`, so the whole path (rpc call →
struct decode → charter decode → IPFS fetch → sha256 compare) is exercised.

## Design notes

- **Dependency-free ABI decoder.** The schema is fixed, so a ~120-line reader that handles
  dynamic strings, `string[]` and `bytes32[]` is smaller and easier to audit than pulling a
  full ABI library into a static page.
- **Two offset rules, deliberately separate.** Top-level offsets are absolute from the start
  of the encoded tuple; offsets inside a dynamic array are relative to the word after the
  length. Mixing the two is the classic bug here — an early version of this module did
  exactly that and the round-trip test caught it.
- **Digests are normalised before comparing** (`0x` stripped, lowercased), because the
  decoder reports `0x`-prefixed hex while the computed value is bare hex.
- **Revoked attestations short-circuit** before any IPFS request and report the reason.
- **Every failure is reported, never thrown silently**: a bad uid, a missing attestation, a
  revoked one, an unreachable CID and a mismatch each produce a populated `reason`.

## Limits, stated plainly

- It trusts the RPC's answer for `getAttestation`; it does not check the attestation is by a
  particular attester. Pass a known-good RPC if that matters to you.
- IPFS is fetched through one gateway at a time; a gateway that lies would produce a
  mismatch verdict rather than a false match, which is the safe direction.
