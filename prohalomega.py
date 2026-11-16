"""Prohalomega v0.2: Deterministic Fail-Closed Verification Gate.

Changes vs v0.1 (razor report 2026-11-16):
  1. SEAL: verdict seal is now HMAC-SHA256 keyed with a secret. A verdict
     without the key cannot be re-forged. Legacy v0.1 seal was an unkeyed
     SHA-256 checksum (proven forgeable in the razor report).
  2. WINDOWS: symlink protection no longer silently depends on O_NOFOLLOW
     (missing on Windows). An explicit pre-open islink() guard blocks
     symlinks on every platform; O_NOFOLLOW is kept as a second layer
     where it exists.
  3. NEW: --verify-verdict re-checks a saved verdict JSON against the key,
     so tampering is detectable after the fact, not just prevented.

Fail-closed rule: every unexpected condition ends in BLOCK + exit code 1.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Final

HASH_LENGTH: Final[int] = 64
CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MiB atomic read buffer
HEX_CHARS: Final[frozenset[str]] = frozenset("0123456789abcdef")
SEAL_ALGORITHM: Final[str] = "HMAC_SHA256_V2"
ENV_KEY_NAME: Final[str] = "PROHALOMEGA_HMAC_KEY"


class _SymlinkBlocked(Exception):
    """Raised when the artifact path is a symbolic link (fail-closed)."""


@dataclasses.dataclass(frozen=True, slots=True)
class ProhalomegaResult:
    """Immutable keyed-sealed deterministic verdict."""

    verdict: str
    reason: str
    artifact_sha256: str
    byte_size: int
    timestamp_utc: str
    verdict_seal: str
    seal_algorithm: str

    @classmethod
    def create(
        cls,
        *,
        verdict: str,
        reason: str,
        artifact_sha256: str,
        byte_size: int,
        timestamp_utc: str,
        seal_key: bytes | None,
    ) -> ProhalomegaResult:
        """Sealed result. With a key the seal is an HMAC (unforgeable without
        the key). Without a key the seal is EMPTY and the verdict honestly
        reports that it is unsealed - it never pretends to be sealed."""
        payload = (
            f"{verdict}|{reason}|{artifact_sha256}|{byte_size}|{timestamp_utc}"
        ).encode("utf-8")
        if seal_key:
            seal = hmac.new(seal_key, payload, hashlib.sha256).hexdigest()
        else:
            seal = ""
        return cls(
            verdict=verdict,
            reason=reason,
            artifact_sha256=artifact_sha256,
            byte_size=byte_size,
            timestamp_utc=timestamp_utc,
            verdict_seal=seal,
            seal_algorithm=SEAL_ALGORITHM,
        )


def _utc_now_iso() -> str:
    """Strict ISO-8601 UTC timestamp."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _is_valid_sha256(candidate: str) -> bool:
    """Exact 64-char lowercase hex."""
    return len(candidate) == HASH_LENGTH and all(ch in HEX_CHARS for ch in candidate)


def _load_seal_key(seal_key_file: Path | None) -> bytes | None:
    """Loads the HMAC secret. env var wins, then key file. Absent -> None
    (verdicts still work, they are just explicitly unsealed)."""
    env_key = os.environ.get(ENV_KEY_NAME, "").strip()
    if env_key:
        return env_key.encode("utf-8")
    if seal_key_file is not None:
        try:
            raw = seal_key_file.read_bytes().strip()
            if raw:
                return raw
        except OSError:
            return None
    return None


def _open_artifact_fd(artifact_path: Path) -> int:
    """Opens the artifact refusing symlinks on EVERY platform.

    Layer 1 (all platforms, incl. Windows): explicit os.path.islink() check
    before open - v0.1 lost this guard silently on Windows because
    O_NOFOLLOW does not exist there.
    Layer 2 (where available): O_NOFOLLOW during open, which also closes
    the pre-open race window on those platforms."""
    if os.path.islink(artifact_path):
        raise _SymlinkBlocked()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(artifact_path, flags)
    if not hasattr(os, "O_NOFOLLOW"):
        # Windows: no O_NOFOLLOW; verify we did not end up on a link.
        if os.path.islink(artifact_path):
            os.close(fd)
            raise _SymlinkBlocked()
    return fd


def evaluate_prohalomega(
    artifact_path: Path,
    expected_sha256: str,
    *,
    seal_key: bytes | None = None,
) -> ProhalomegaResult:
    """Atomically evaluates filesystem evidence against strict invariants."""
    timestamp = _utc_now_iso()
    normalized_expected = expected_sha256.strip().lower()

    def block(reason: str, sha: str = "", size: int = 0) -> ProhalomegaResult:
        return ProhalomegaResult.create(
            verdict="BLOCK",
            reason=reason,
            artifact_sha256=sha,
            byte_size=size,
            timestamp_utc=timestamp,
            seal_key=seal_key,
        )

    if not _is_valid_sha256(normalized_expected):
        return block("INVALID_EXPECTED_HASH_FORMAT")

    try:
        fd = _open_artifact_fd(artifact_path)
    except FileNotFoundError:
        return block("ARTIFACT_MISSING")
    except _SymlinkBlocked:
        return block("ARTIFACT_OPEN_OR_SYMLINK_BLOCKED")
    except OSError:
        return block("ARTIFACT_OPEN_OR_SYMLINK_BLOCKED")

    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            return block("NOT_A_REGULAR_FILE")
        if file_stat.st_size <= 0:
            return block("ZERO_BYTE_ARTIFACT")

        hasher = hashlib.sha256()
        total_read = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while chunk := stream.read(CHUNK_SIZE):
                total_read += len(chunk)
                hasher.update(chunk)

        if total_read != file_stat.st_size:
            return block("READ_SIZE_MISMATCH", size=total_read)
        measured_hash = hasher.hexdigest()
    except OSError:
        return block("IO_STREAM_READ_FAILURE")
    finally:
        os.close(fd)

    if not hmac.compare_digest(normalized_expected, measured_hash):
        return block("SHA256_MISMATCH", sha=measured_hash, size=total_read)

    return ProhalomegaResult.create(
        verdict="APPROVE",
        reason="BALANCED_1_TO_1",
        artifact_sha256=measured_hash,
        byte_size=total_read,
        timestamp_utc=timestamp,
        seal_key=seal_key,
    )


def verify_verdict_json(verdict_path: Path, seal_key: bytes | None) -> tuple[str, str]:
    """Re-checks a saved verdict file against the keyed seal.

    Returns (status, detail): SEALED_VALID or SEALED_INVALID_* / UNSEALED.
    Fail-closed: any missing key, field or mismatch -> INVALID."""
    try:
        data = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "SEALED_INVALID_FILE", "unreadable or not JSON"
    if not isinstance(data, dict):
        return "SEALED_INVALID_FILE", "not an object"
    if data.get("seal_algorithm") != SEAL_ALGORITHM:
        return "SEALED_INVALID_FILE", "unknown seal algorithm"
    if not seal_key:
        return "UNSEALED_VERDICT", "no seal key provided"
    fields = (data.get("verdict"), data.get("reason"), data.get("artifact_sha256"),
              data.get("byte_size"), data.get("timestamp_utc"))
    if any(not isinstance(f, (str, int)) for f in fields):
        return "SEALED_INVALID_FILE", "missing or mistyped fields"
    payload = f"{fields[0]}|{fields[1]}|{fields[2]}|{fields[3]}|{fields[4]}".encode("utf-8")
    expected = hmac.new(seal_key, payload, hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, str(data.get("verdict_seal", ""))):
        return "SEALED_VALID", "seal matches"
    return "SEALED_INVALID_SEAL", "seal does not match content (tampered or wrong key)"


def _run_self_diagnostics() -> int:
    """Deterministic self-verification battery, incl. seal + symlink tests."""
    ok = True
    report: dict[str, object] = {"engine": "PROHALOMEGA_CORE_V02"}
    self_path = Path(__file__).resolve()
    raw = self_path.read_bytes()
    expected = hashlib.sha256(raw).hexdigest()
    key = b"razor-self-test-key-16-11-2026"

    res_approve = evaluate_prohalomega(self_path, expected, seal_key=key)
    res_block = evaluate_prohalomega(self_path, "0" * HASH_LENGTH, seal_key=key)
    res_unsealed = evaluate_prohalomega(self_path, expected)
    report["self_test_approve"] = dataclasses.asdict(res_approve)
    report["self_test_fail_closed"] = dataclasses.asdict(res_block)
    report["self_test_unsealed_is_empty_seal"] = res_unsealed.verdict_seal == ""

    ok = ok and res_approve.verdict == "APPROVE" and res_block.verdict == "BLOCK"
    ok = ok and res_unsealed.verdict_seal == ""

    # Seal tamper test: forge a verdict with the WRONG key -> must not validate.
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        art = tdp / "a.txt"
        art.write_bytes(b"prohalomega v0.2 seal test")
        h = hashlib.sha256(art.read_bytes()).hexdigest()
        good = evaluate_prohalomega(art, h, seal_key=key)
        vfile = tdp / "verdict.json"
        vfile.write_text(json.dumps(dataclasses.asdict(good)), encoding="utf-8")
        status_good, _ = verify_verdict_json(vfile, key)
        status_wrong_key, _ = verify_verdict_json(vfile, b"attacker-guessed-key")
        forged = dict(dataclasses.asdict(good))
        forged["verdict"] = "APPROVE" if good.verdict == "BLOCK" else "APPROVE"
        forged["reason"] = "TAMPERED"
        ffile = tdp / "forged.json"
        ffile.write_text(json.dumps(forged), encoding="utf-8")
        status_forged, _ = verify_verdict_json(ffile, key)
        report["seal_check_good"] = status_good
        report["seal_check_wrong_key"] = status_wrong_key
        report["seal_check_tampered"] = status_forged
        ok = ok and status_good == "SEALED_VALID"
        ok = ok and status_wrong_key != "SEALED_VALID"
        ok = ok and status_forged == "SEALED_INVALID_SEAL"

        # Symlink test: on Linux O_NOFOLLOW; the pre-check covers Windows.
        ln = tdp / "link_to_a"
        try:
            ln.symlink_to(art)
            res_link = evaluate_prohalomega(ln, h, seal_key=key)
            report["symlink_blocked"] = res_link.verdict == "BLOCK"
            report["symlink_reason"] = res_link.reason
            ok = ok and res_link.verdict == "BLOCK"
        except (OSError, NotImplementedError):
            report["symlink_blocked"] = "SKIPPED (platform)"

        # Empty file, directory, missing file.
        empty = tdp / "empty.txt"
        empty.touch()
        report["empty_blocked"] = evaluate_prohalomega(empty, h, seal_key=key).reason
        ok = ok and report["empty_blocked"] == "ZERO_BYTE_ARTIFACT"
        report["dir_blocked"] = evaluate_prohalomega(tdp, h, seal_key=key).reason
        ok = ok and report["dir_blocked"] == "NOT_A_REGULAR_FILE"
        report["missing_blocked"] = evaluate_prohalomega(
            tdp / "nope.txt", h, seal_key=key).reason
        ok = ok and report["missing_blocked"] == "ARTIFACT_MISSING"

    print(json.dumps(report, indent=2))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="prohalomega",
        description="Deterministic Fail-Closed Artifact Verification Gate v0.2",
    )
    parser.add_argument("--file", type=Path, help="Path to target artifact on disk")
    parser.add_argument("--sha256", type=str, help="Expected 64-char SHA-256 hex digest")
    parser.add_argument("--seal-key-file", type=Path,
                        help="File with the HMAC secret (or env %s)" % ENV_KEY_NAME)
    parser.add_argument("--verify-verdict", type=Path,
                        help="Re-check a saved verdict JSON against the seal key")
    parser.add_argument("--self-test", action="store_true",
                        help="Run built-in deterministic verification battery")
    args = parser.parse_args(argv)

    if args.self_test:
        return _run_self_diagnostics()

    seal_key = _load_seal_key(args.seal_key_file)

    if args.verify_verdict is not None:
        if seal_key is None:
            print(json.dumps({"status": "UNSEALED_VERDICT",
                              "detail": "no seal key provided"}))
            return 1
        status, detail = verify_verdict_json(args.verify_verdict, seal_key)
        print(json.dumps({"status": status, "detail": detail}))
        return 0 if status == "SEALED_VALID" else 1

    if args.file is None and args.sha256 is None:
        return _run_self_diagnostics()

    if args.file is None or args.sha256 is None:
        fail = ProhalomegaResult.create(
            verdict="BLOCK",
            reason="MISSING_CLI_ARGUMENTS_FAIL_CLOSED",
            artifact_sha256="",
            byte_size=0,
            timestamp_utc=_utc_now_iso(),
            seal_key=seal_key,
        )
        print(json.dumps(dataclasses.asdict(fail), indent=2))
        return 1

    result = evaluate_prohalomega(args.file, args.sha256, seal_key=seal_key)
    print(json.dumps(dataclasses.asdict(result), indent=2))
    return 0 if result.verdict == "APPROVE" else 1


if __name__ == "__main__":
    sys.exit(main())