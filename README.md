# Prohalogen — Prohalomega Gate

**A deterministic, fail-closed artifact verification gate. One file. Zero dependencies. Pure Python stdlib.**

By **Damir Balenović** (BodulAI), 2026. MIT License.

## What it is

Prohalomega answers exactly one question, and answers it honestly:

> *Is this file on disk exactly the one I claim it is?*

It computes the SHA-256 of an artifact, compares it to the expected digest in
constant time, and returns one of two verdicts:

- `APPROVE` — measured digest matches, exit code `0`
- `BLOCK` — anything else, exit code `1`

**Fail-closed by construction:** a missing file, an empty file, a directory, a
symlink, a wrong digest format, a hash mismatch, an I/O error — every
unexpected path ends in `BLOCK`. There is no branch that continues without
verification. The tool never guesses, never "probably works".

## Why

Because "trust me, it works" is not evidence. Prohalomega is a small piece of
the Prohalogen doctrine: **proof over claims**. Every verdict is a sealed,
reproducible, machine-checkable record — not a promise.

## Install

There is nothing to install. Copy `prohalomega.py` anywhere with Python 3.10+.

## Quick start

```bash
# Built-in deterministic self-test (APPROVE + BLOCK battery):
python prohalomega.py --self-test

# Verify a file:
python prohalomega.py --file your_artifact.bin --sha256 <64-hex-digest>
```

Compute the expected digest first:

```bash
sha256sum your_artifact.bin
```

## Verdict reasons

| Reason | Meaning |
|---|---|
| `BALANCED_1_TO_1` | Digest matches (APPROVE) |
| `SHA256_MISMATCH` | Content differs from the expected digest |
| `INVALID_EXPECTED_HASH_FORMAT` | Digest is not 64 lowercase hex chars |
| `ARTIFACT_MISSING` | File does not exist |
| `ARTIFACT_OPEN_OR_SYMLINK_BLOCKED` | Symlink or unreadable path (symlinks are refused on every OS, including Windows) |
| `NOT_A_REGULAR_FILE` | Path is a directory/device, not a regular file |
| `ZERO_BYTE_ARTIFACT` | File is empty |
| `READ_SIZE_MISMATCH` | File changed size while being read (TOCTOU guard) |
| `IO_STREAM_READ_FAILURE` | Read error mid-stream |
| `MISSING_CLI_ARGUMENTS_FAIL_CLOSED` | Incomplete CLI invocation |

## Optional: keyed verdict seals

Every verdict carries a `verdict_seal`. By default it is empty and the verdict
honestly reports itself as unsealed — a seal is never faked.

With a secret key the seal becomes an HMAC-SHA256 that cannot be recomputed
without the key, and a saved verdict JSON can be re-checked at any time:

```bash
# Seal with a key file (or env var PROHALOMEGA_HMAC_KEY):
python prohalomega.py --file artifact.bin --sha256 <digest> --seal-key-file key.txt

# Re-verify a saved verdict later:
python prohalomega.py --verify-verdict verdict.json --seal-key-file key.txt
```

`--verify-verdict` prints `SEALED_VALID`, `SEALED_INVALID_SEAL` (tampered or
wrong key) or `UNSEALED_VERDICT`, and fails closed (exit `1`) on anything but
`SEALED_VALID`.

## Engineering notes

- The file is opened once via a file descriptor and all checks run against
  that same descriptor, closing the classic TOCTOU window between "stat" and
  "read".
- Digest comparison uses `hmac.compare_digest` (constant time).
- Symlink refusal is explicit on every platform — it does not silently
  depend on `O_NOFOLLOW`, which does not exist on Windows.
- Read size is compared against the stat size; a file that changes while
  being hashed is rejected.
- Verdict objects are immutable (`frozen=True, slots=True`).

## License

MIT — see [LICENSE](LICENSE). Attribution: Damir Balenović / BodulAI, 2026.