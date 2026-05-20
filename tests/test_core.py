from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from honeypot_orchestrator.config import load_config, parse_simple_yaml
from honeypot_orchestrator.orchestrator import Orchestrator
from honeypot_orchestrator.profiles import load_profile
from honeypot_orchestrator.services import SERVICE_REGISTRY


class ConfigTests(unittest.TestCase):
    def test_parse_simple_yaml_nested_scalars(self) -> None:
        payload = parse_simple_yaml(
            """
            host: "127.0.0.1"
            web:
              enabled: true
              port: 8000
            """
        )

        self.assertEqual(payload["host"], "127.0.0.1")
        self.assertEqual(payload["web"]["enabled"], True)
        self.assertEqual(payload["web"]["port"], 8000)

    def test_load_config_rejects_conflicting_bind_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                """
                web:
                  enabled: true
                  host: "0.0.0.0"
                  port: 8000
                services:
                  http:
                    enabled: true
                    host: "127.0.0.1"
                    port: 8000
                """,
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_config(path)


class RegistryTests(unittest.TestCase):
    def test_profiles_reference_registered_services(self) -> None:
        for profile_name in ("empty", "linux_server", "windows_server"):
            profile = load_profile(profile_name)
            unknown = set(profile.services) - set(SERVICE_REGISTRY)
            self.assertEqual(unknown, set())

    def test_orchestrator_builds_only_configured_known_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(
                """
                profile: "empty"
                logging:
                  path: "events.jsonl"
                web:
                  enabled: true
                  host: "127.0.0.1"
                  port: 8000
                auth:
                  username: "admin"
                  password: "admin123"
                services:
                  http:
                    enabled: true
                    host: "127.0.0.1"
                    port: 8080
                  unknown:
                    enabled: true
                    host: "127.0.0.1"
                    port: 9090
                """,
                encoding="utf-8",
            )
            config = load_config(config_path)
            config = replace(
                config,
                logging=replace(config.logging, path=Path(directory) / config.logging.path),
            )
            orchestrator = Orchestrator(config)

            self.assertEqual(set(orchestrator.services), set(config.services) & set(SERVICE_REGISTRY))


if __name__ == "__main__":
    unittest.main()
