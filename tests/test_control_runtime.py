import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from prj226_runner.control_runtime import canonical_role_body, derived_profile_ref, validate_runtime
from prj226_runner.errors import ArtifactValidationError


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.executable = Path(self.temp.name) / "fake-runtime"
        self.executable.write_text("#!/bin/sh\nprintf 'codex-cli 0.148.0\\n'\n")
        self.executable.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def bundle(self):
        digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        roles = {}
        for name, capability in (("planner", "none"), ("builder", "candidate-write-only"), ("reviewer", "none")):
            role = {"role": name.upper(), "backend": "codex", "provider": "openai", "model": "test-model", "adapter": "test-adapter", "executable": str(self.executable), "executable_sha256": digest, "version": "codex-cli 0.148.0", "policy": {"sandbox": "workspace-write", "approval": "never", "tool_capability": capability, "shell_capability": "workspace-only", "repository_write_capability": "candidate-worktree-owned-paths", "network_capability": "provider-api-only", "retry_count": 0, "fallback_count": 0, "fresh_home": True, "fresh_codex_home": True, "session_persistence": "ephemeral-isolated", "environment_policy": "closed-allowlist-only", "authentication_policy": "no-auth-required", "timeout_seconds": 5, "context_policy": "test", "feature_disables": []}}
            role["profile_ref"] = derived_profile_ref(role)
            roles[name] = role
        return {"schema_version": "PRJ226.CONTROL_RUNTIME.v1", "roles": roles}

    def test_validate_runtime_schema_compliance(self):
        self.assertEqual(validate_runtime(self.bundle())["schema_version"], "PRJ226.CONTROL_RUNTIME.v1")

    def test_executable_sha256_mismatch_fails_pre_dispatch(self):
        bundle = self.bundle(); bundle["roles"]["planner"]["executable_sha256"] = "0" * 64
        with self.assertRaises(ArtifactValidationError): validate_runtime(bundle)

    def test_symlink_executable_rejected(self):
        link = Path(self.temp.name) / "link"; link.symlink_to(self.executable)
        bundle = self.bundle(); bundle["roles"]["planner"]["executable"] = str(link); bundle["roles"]["planner"]["executable_sha256"] = hashlib.sha256(link.read_bytes()).hexdigest(); bundle["roles"]["planner"]["profile_ref"] = derived_profile_ref(bundle["roles"]["planner"])
        with self.assertRaises(ArtifactValidationError): validate_runtime(bundle)

    def test_all_expanded_role_fields_validated(self):
        bundle = self.bundle(); bundle["roles"]["planner"]["policy"]["environment_policy"] = "open"
        bundle["roles"]["planner"]["profile_ref"] = derived_profile_ref(bundle["roles"]["planner"])
        with self.assertRaises(ArtifactValidationError): validate_runtime(bundle)

    def test_authority_widening_policies_rejected(self):
        bundle = self.bundle(); bundle["roles"]["builder"]["policy"]["retry_count"] = 1
        with self.assertRaises(ArtifactValidationError): validate_runtime(bundle)

    def test_profile_ref_digest_integrity(self):
        bundle = self.bundle(); self.assertEqual(bundle["roles"]["planner"]["profile_ref"], derived_profile_ref(bundle["roles"]["planner"]))
        bundle["roles"]["planner"]["model"] = "mutated"
        with self.assertRaises(ArtifactValidationError): validate_runtime(bundle)

    def test_canonical_serialization_is_deterministic(self):
        profile = self.bundle()["roles"]["planner"]
        self.assertEqual(canonical_role_body(profile), canonical_role_body(dict(reversed(list(profile.items())))))

    def test_version_mismatch_is_observed_and_rejected(self):
        bundle = self.bundle(); bundle["roles"]["reviewer"]["version"] = "expected-but-false"; bundle["roles"]["reviewer"]["profile_ref"] = derived_profile_ref(bundle["roles"]["reviewer"])
        with self.assertRaises(ArtifactValidationError): validate_runtime(bundle)

    def test_display_provider_name_is_rejected(self):
        bundle = self.bundle(); bundle["roles"]["planner"]["provider"] = "OpenAI"
        bundle["roles"]["planner"]["profile_ref"] = derived_profile_ref(bundle["roles"]["planner"])
        with self.assertRaises(ArtifactValidationError): validate_runtime(bundle)


if __name__ == "__main__":
    unittest.main()
