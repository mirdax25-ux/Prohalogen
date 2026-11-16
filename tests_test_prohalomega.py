import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from prohalomega import evaluate_prohalomega, verify_verdict_json


class VerifyVerdictJsonTests(unittest.TestCase):
    def test_tampering_with_each_signed_field_invalidates_seal(self):
        key = b"test-seal-key"
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.bin"
            artifact.write_bytes(b"verified artifact")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            result = evaluate_prohalomega(artifact, digest, seal_key=key)
            verdict_path = Path(directory) / "verdict.json"

            self.assertEqual(
                verify_verdict_json(
                    self._write_verdict(verdict_path, dataclasses.asdict(result)), key
                )[0],
                "SEALED_VALID",
            )

            mutations = {
                "verdict": "BLOCK" if result.verdict == "APPROVE" else "APPROVE",
                "reason": "TAMPERED",
                "artifact_sha256": "0" * 64,
                "byte_size": result.byte_size + 1,
                "timestamp_utc": result.timestamp_utc + "tampered",
            }
            for field, value in mutations.items():
                with self.subTest(field=field):
                    tampered = dataclasses.asdict(result)
                    tampered[field] = value
                    self._write_verdict(verdict_path, tampered)
                    self.assertEqual(
                        verify_verdict_json(verdict_path, key)[0],
                        "SEALED_INVALID_SEAL",
                    )

    @staticmethod
    def _write_verdict(path: Path, verdict: dict[str, object]) -> Path:
        path.write_text(json.dumps(verdict), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
