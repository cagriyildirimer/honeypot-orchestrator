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


class DefenseTests(unittest.TestCase):
    def setUp(self) -> None:
        import honeypot_orchestrator.defense as defense
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_whitelist = defense.WHITELIST_PATH
        self.original_blacklist = defense.BLACKLIST_PATH
        defense.WHITELIST_PATH = Path(self.temp_dir.name) / "whitelist.json"
        defense.BLACKLIST_PATH = Path(self.temp_dir.name) / "blacklist.json"
        defense._suspicious_counters.clear()

    def tearDown(self) -> None:
        import honeypot_orchestrator.defense as defense
        defense.WHITELIST_PATH = self.original_whitelist
        defense.BLACKLIST_PATH = self.original_blacklist
        self.temp_dir.cleanup()

    def test_whitelist_crud(self) -> None:
        import honeypot_orchestrator.defense as defense
        self.assertFalse(defense.is_whitelisted("192.168.1.10"))
        self.assertTrue(defense.add_to_whitelist("192.168.1.10", "Test whitelist"))
        self.assertTrue(defense.is_whitelisted("192.168.1.10"))
        self.assertFalse(defense.add_to_whitelist("192.168.1.10", "Duplicate"))
        self.assertTrue(defense.delete_from_whitelist("192.168.1.10"))
        self.assertFalse(defense.is_whitelisted("192.168.1.10"))

    def test_blacklist_crud(self) -> None:
        import honeypot_orchestrator.defense as defense
        self.assertFalse(defense.is_blacklisted("192.168.1.20"))
        self.assertTrue(defense.add_to_blacklist("192.168.1.20", "Test blacklist"))
        self.assertTrue(defense.is_blacklisted("192.168.1.20"))
        self.assertFalse(defense.add_to_blacklist("192.168.1.20", "Duplicate"))
        self.assertTrue(defense.delete_from_blacklist("192.168.1.20"))
        self.assertFalse(defense.is_blacklisted("192.168.1.20"))

    def test_auto_ban_threshold(self) -> None:
        import honeypot_orchestrator.defense as defense
        ip = "192.168.1.30"
        for _ in range(99):
            defense.record_suspicious_event(ip)
        self.assertFalse(defense.is_blacklisted(ip))
        
        # 100th event triggers auto-ban
        defense.record_suspicious_event(ip)
        self.assertTrue(defense.is_blacklisted(ip))

    def test_auto_ban_does_not_ban_whitelisted(self) -> None:
        import honeypot_orchestrator.defense as defense
        ip = "192.168.1.40"
        defense.add_to_whitelist(ip, "Allowed scanner")
        for _ in range(150):
            defense.record_suspicious_event(ip)
        self.assertFalse(defense.is_blacklisted(ip))


if __name__ == "__main__":
    unittest.main()
