"""Cross-platform regression checks; never call the host firewall."""
import copy
from contextlib import nullcontext, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import time
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import vps_firewall as app


def config(**overrides):
    cfg = copy.deepcopy(app.DEFAULTS)
    cfg.update(rescue_ips=["192.0.2.1"])
    cfg.update(overrides)
    return app.validate_config(cfg)


class ConfigAndRules(unittest.TestCase):
    def test_roundtrip_and_defaults_for_old_config(self):
        cfg = app.validate_config({"rescue_ips": ["192.0.2.1"], "provinces": ["广东省", "粤"]})
        self.assertEqual(cfg["provinces"], ["广东"])
        self.assertEqual(tomllib.loads(app.dump_config(cfg)), cfg)

    def test_reject_bad_config_instead_of_partial_apply(self):
        for changes in ({"ips": ["not-an-ip"]}, {"ips": ["::/0"]},
                        {"enabled": "false"}, {"watch_interval": 0}, {"province_refresh": -1},
                        {"provinces": ["不存在"]}, {"ips": "192.0.2.2"},
                        {"rescue_ips": []}, {"blocked_ips": ["192.0.2.1"]},
                        {"province_source_base": "file:///etc/passwd"}, {"extra": 1}):
            with self.subTest(changes=changes), self.assertRaises(app.AppError):
                config(**changes)

    def test_ipv6_and_overlapping_networks(self):
        values = ["2001:db8::1", "2001:db8::/64", "192.0.2.18/24", "192.0.2.1"]
        self.assertEqual(app.collapse(values, 4), ["192.0.2.0/24"])
        self.assertEqual(app.collapse(values, 6), ["2001:db8::/64"])
        self.assertEqual(app.norm("2001:db8::FFFF"), "2001:db8::ffff")

    def test_removed_ssh_ip_is_not_implicitly_added(self):
        with patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.9 1234 192.0.2.2 2222"}):
            self.assertEqual(app.build_allowlist(config()), {"192.0.2.1"})

    def test_ssh_source_accepts_ipv6_and_custom_port(self):
        with patch.dict(os.environ, {"SSH_CONNECTION": "2001:db8::9 1234 2001:db8::2 22000"}):
            self.assertEqual(app.ssh_source(), "2001:db8::9")

    def test_inbound_established_no_longer_bypasses_membership(self):
        rules = app.render_rules(["192.0.2.1", "2001:db8::1"])
        self.assertNotIn("        ct state established,related accept", rules)
        self.assertIn("ct direction reply ct state established,related accept", rules)
        self.assertIn("ct status dnat ct direction original jump published", rules)
        self.assertIn("set allow6", rules)
        self.assertIn("nd-neighbor-solicit", rules)

    def test_explicit_deny_precedes_global_ipv6_allow(self):
        rules = app.render_rules(["2001:db8::/32"], allow_all_ipv6=True, blocked_ips=["2001:db8::2"])
        self.assertLess(rules.index("ip6 saddr @blocked6"), rules.index("meta nfproto ipv6 accept"))

    def test_disabled_rules_only_remove_own_table(self):
        rules = app.render_rules([], enabled=False)
        self.assertEqual(rules, "add table inet vps_wl\ndelete table inet vps_wl\n")
        self.assertNotIn("flush ruleset", rules)

    def test_rule_replacement_and_disable_are_single_atomic_nft_commands(self):
        for rules in (app.render_rules(["192.0.2.1"]), app.render_rules([], enabled=False)):
            with patch.object(app, "run", return_value=SimpleNamespace(returncode=0)) as run:
                app.nft(rules)
                run.assert_called_once_with(["nft", "-f", "-"], rules)
                self.assertTrue(rules.startswith("add table inet vps_wl\ndelete table inet vps_wl\n"))

    def test_rescue_network_cannot_be_blocked(self):
        with self.assertRaises(app.AppError):
            config(rescue_ips=["192.0.2.0/24"], blocked_ips=["192.0.2.9"])

    def test_province_payload_must_be_real_networks(self):
        for payload in ("<html>error</html>", "", "::/0", "192.0.2.0/24\nbad"):
            with self.assertRaises(app.AppError):
                app.parse_province(payload)
        self.assertEqual(app.parse_province("# comment\n192.0.2.0/24"), {"192.0.2.0/24"})


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, value in dict(CONFIG_PATH=str(self.root / "config.toml"),
                                DATA_DIR=str(self.root), CACHE_DIR=str(self.root / "cache"),
                                STATE_PATH=str(self.root / "state.json"),
                                SYSTEM_RULES_PATH=str(self.root / "nftables.conf")).items():
            patcher = patch.object(app, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(app, "operation_lock", nullcontext)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.output = io.StringIO()
        capture = redirect_stdout(self.output)
        capture.__enter__()
        self.addCleanup(capture.__exit__, None, None, None)
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config()))

    def install_fake_nft(self):
        self.rules = app.render_rules([], enabled=False)
        self.calls = []

        def nft(text, check=False):
            self.calls.append((text, check))
            if not check:
                self.rules = text

        for name, target in (("nft", nft), ("live_snapshot", lambda: self.rules)):
            p = patch.object(app, name, target)
            p.start()
            self.addCleanup(p.stop)


class Transactions(Workspace):
    def setUp(self):
        super().setUp()
        self.install_fake_nft()

    def test_apply_delete_and_rollback_restores_config_and_rules(self):
        app.apply_once()
        first = self.rules
        original = app.load_config()
        added = config(ips=["192.0.2.8"])
        app.edit_config(original, added)
        added_rules = self.rules
        self.assertIn("192.0.2.8/32", added_rules)
        app.edit_config(added, original)
        self.assertEqual(self.rules, first)
        app.rollback()
        self.assertEqual(app.load_config(), added)
        self.assertEqual(self.rules, added_rules)
        self.assertFalse(app.journal_path().exists())

    def test_unchanged_apply_does_not_destroy_backup(self):
        app.apply_once()
        old = app.load_config()
        app.edit_config(old, config(ips=["192.0.2.8"]))
        backup = app.read_state()["previous"]
        app.apply_once()
        self.assertEqual(app.read_state()["previous"], backup)

    def test_test_does_not_write_rules_config_state_or_cache(self):
        initial = Path(app.CONFIG_PATH).read_bytes()
        app.apply_once(dry_run=True)
        self.assertEqual(Path(app.CONFIG_PATH).read_bytes(), initial)
        self.assertFalse(Path(app.STATE_PATH).exists())
        self.assertFalse(Path(app.CACHE_DIR).exists())
        self.assertTrue(all(check for _, check in self.calls))

    def test_rejected_rules_leave_config_unchanged(self):
        app.apply_once()
        initial = Path(app.CONFIG_PATH).read_bytes()
        with patch.object(app, "nft", side_effect=app.AppError("syntax rejected")):
            with self.assertRaises(app.AppError):
                app.edit_config(app.load_config(), config(ips=["192.0.2.8"]))
        self.assertEqual(Path(app.CONFIG_PATH).read_bytes(), initial)
        self.assertFalse(app.journal_path().exists())

    def test_disk_failure_restores_live_rules_and_config(self):
        app.apply_once()
        original = app.load_config()
        previous_rules = self.rules
        old_state = app.read_state()
        real_write = app.atomic_write

        def fail_state(path, text):
            if str(path) == app.STATE_PATH:
                raise OSError("disk full")
            return real_write(path, text)

        with patch.object(app, "atomic_write", side_effect=fail_state):
            with self.assertRaises(app.AppError):
                app.edit_config(original, config(ips=["192.0.2.8"]))
        self.assertEqual(app.load_config(), original)
        self.assertEqual(self.rules, previous_rules)
        self.assertEqual(app.read_state(), old_state)
        self.assertFalse(app.journal_path().exists())

    def test_stale_menu_cannot_overwrite_other_writer(self):
        original = app.load_config()
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(ips=["192.0.2.9"])))
        with self.assertRaises(app.AppError):
            app.edit_config(original, config(ips=["192.0.2.8"]))
        self.assertFalse(self.calls)

    def test_boot_uses_snapshot_without_download(self):
        app.apply_once()
        snapshot = self.rules
        with patch.object(app, "fetch_provinces", side_effect=AssertionError("network forbidden")):
            app.boot()
        self.assertEqual(self.rules, snapshot)

    def test_daemon_survives_bad_initial_config(self):
        with patch.object(app, "load_config", side_effect=ValueError("invalid toml")), \
                patch.object(app.time, "sleep", side_effect=SystemExit) as sleep:
            with self.assertRaises(SystemExit):
                app.daemon()
            sleep.assert_called_once_with(5)

    def test_daemon_does_not_overwrite_menu_or_rollback_snapshot(self):
        app.apply_once()
        with patch.object(app, "live_table", return_value=True), \
                patch.object(app, "apply_once") as apply, \
                patch.object(app.time, "sleep", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                app.daemon()
            apply.assert_not_called()

    def test_interrupted_transaction_recovers_old_config_and_policy(self):
        app.apply_once()
        before = self.rules
        original = app.load_config()
        candidate = config(ips=["192.0.2.8"])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(candidate))
        self.rules = app.prepare(candidate)
        pending = dict(after={"different": True}, rules_before=before,
                       config_before=app.dump_config(original), save=True)
        app.atomic_write(app.journal_path(), json.dumps(pending))
        app.recover_pending()
        self.assertEqual(self.rules, before)
        self.assertEqual(app.load_config(), original)
        self.assertFalse(app.journal_path().exists())

    def test_interrupted_cleanup_keeps_committed_policy(self):
        app.apply_once()
        before = self.rules
        state = app.read_state()
        pending = dict(after=state, rules_before="old rules", config_before="old config", save=True)
        app.atomic_write(app.journal_path(), json.dumps(pending))
        app.recover_pending()
        self.assertEqual(self.rules, before)
        self.assertEqual(app.load_config(), state["current"]["config"])

    def test_change_during_download_is_not_committed(self):
        original = app.load_config()

        def change_file(*args, **kwargs):
            app.atomic_write(app.CONFIG_PATH, app.dump_config(config(ips=["192.0.2.99"])))
            return "unused"

        with patch.object(app, "prepare", side_effect=change_file):
            with self.assertRaises(app.AppError):
                app.edit_config(original, config(ips=["192.0.2.8"]))
        self.assertFalse(self.calls)


class CacheAndMigration(Workspace):
    def test_failed_download_preserves_old_cache_time(self):
        path = Path(app.CACHE_DIR) / "440000.txt"
        app.atomic_write(path, "192.0.2.0/24\n")
        timestamp = time.time() - 99999
        os.utime(path, (timestamp, timestamp))
        before = path.stat().st_mtime
        with patch.object(app.urllib.request, "urlopen", side_effect=OSError("offline")):
            result = app.fetch_provinces(["广东"], 86400, ["https://example.invalid"])
        self.assertEqual(result, {"192.0.2.0/24"})
        self.assertEqual(path.stat().st_mtime, before)

    def test_unavailable_province_aborts_instead_of_partial_whitelist(self):
        with patch.object(app.urllib.request, "urlopen", side_effect=OSError("offline")):
            with self.assertRaises(app.AppError):
                app.fetch_provinces(["广东"], 0, ["https://example.invalid"])

    def test_zero_refresh_reuses_cache(self):
        app.atomic_write(Path(app.CACHE_DIR) / "440000.txt", "192.0.2.0/24")
        with patch.object(app.urllib.request, "urlopen", side_effect=AssertionError("no fetch")):
            self.assertEqual(app.fetch_provinces(["广东"], 0, ["https://example.invalid"]), {"192.0.2.0/24"})

    def test_migration_restores_original_before_data_removal(self):
        original = "flush ruleset\ntable inet other {}\n"
        app.atomic_write(Path(app.DATA_DIR) / "nftables.conf.orig", original)
        old = "flush table inet vps_wl\ntable inet vps_wl {\n chain input { policy drop; }\n}\n"
        app.atomic_write(app.SYSTEM_RULES_PATH, old)
        app.migrate_legacy()
        self.assertEqual(Path(app.SYSTEM_RULES_PATH).read_text(encoding="utf-8"), original)
        self.assertEqual((Path(app.DATA_DIR) / "legacy-nftables.conf").read_text(encoding="utf-8"), old)

    def test_migration_never_overwrites_other_rules(self):
        other = "table inet other {}\n"
        app.atomic_write(app.SYSTEM_RULES_PATH, other)
        app.migrate_legacy()
        self.assertEqual(Path(app.SYSTEM_RULES_PATH).read_text(encoding="utf-8"), other)

    def test_mixed_legacy_rules_fail_without_overwrite(self):
        mixed = "flush table inet vps_wl\ntable inet vps_wl {}\ntable inet other {}\n"
        app.atomic_write(app.SYSTEM_RULES_PATH, mixed)
        with self.assertRaises(app.AppError):
            app.migrate_legacy()
        self.assertEqual(Path(app.SYSTEM_RULES_PATH).read_text(encoding="utf-8"), mixed)

    def test_reinstall_preserves_existing_configuration(self):
        initial = Path(app.CONFIG_PATH).read_bytes()
        app.initialize("192.0.2.99")
        self.assertEqual(Path(app.CONFIG_PATH).read_bytes(), initial)

    def test_first_install_saves_explicit_and_current_ssh_addresses(self):
        Path(app.CONFIG_PATH).unlink()
        with patch.object(app, "ssh_source", return_value="2001:db8::9"):
            app.initialize("192.0.2.99")
        self.assertEqual(app.load_config()["rescue_ips"], ["192.0.2.99", "2001:db8::9"])

    def test_invalid_replacement_download_does_not_poison_cache(self):
        path = Path(app.CACHE_DIR) / "440000.txt"
        app.atomic_write(path, "192.0.2.0/24\n")
        with patch.object(app.urllib.request, "urlopen", return_value=io.BytesIO(b"<html>bad gateway</html>")):
            result = app.fetch_provinces(["广东"], 0, ["https://example.invalid"], force=True)
        self.assertEqual(result, {"192.0.2.0/24"})
        self.assertEqual(path.read_text(), "192.0.2.0/24\n")


class ProgramMenu(Workspace):
    def run_menu(self, choices, returncode=0, restart_error=None):
        with patch.object(app, "read_choice", side_effect=choices), \
                patch.object(app, "live_table", return_value=True), \
                patch.object(app, "ssh_source", return_value=None), \
                patch.object(app.subprocess, "call", return_value=returncode) as command, \
                patch.object(app.os, "execv", side_effect=restart_error) as restart:
            result = app.interactive_menu()
        return result, command, restart

    def test_cancel_update_and_uninstall_never_launches_commands(self):
        for choice in ("8", "9"):
            for answer in ("0", ""):
                with self.subTest(choice=choice, answer=answer):
                    result, command, restart = self.run_menu([choice, answer, "0"])
                    self.assertEqual(result, 0)
                    command.assert_not_called()
                    restart.assert_not_called()

    def test_successful_update_replaces_menu_with_installed_program(self):
        result, command, restart = self.run_menu(["8", "1"])
        self.assertEqual(result, 0)
        command.assert_called_once_with([app.sys.executable,
                                         str(Path(app.__file__).with_name("github_install.py"))])
        restart.assert_called_once_with(app.sys.executable,
                                        [app.sys.executable, "/opt/vps-firewall/vps_firewall.py", "menu"])

    def test_successful_uninstall_exits_without_reading_deleted_config(self):
        result, command, restart = self.run_menu(["9", "1"])
        self.assertEqual(result, 0)
        command.assert_called_once_with(["bash", str(Path(app.__file__).with_name("uninstall.sh")), "--yes"])
        restart.assert_not_called()

    def test_failed_update_and_uninstall_exits_without_restart(self):
        for choice in ("8", "9"):
            with self.subTest(choice=choice):
                result, command, restart = self.run_menu([choice, "1"], returncode=1)
                self.assertEqual(result, 1)
                command.assert_called_once()
                restart.assert_not_called()
        self.assertIn("未完成", self.output.getvalue())

    def test_failed_menu_restart_does_not_continue_using_old_code(self):
        result, command, restart = self.run_menu(["8", "1"], restart_error=OSError("missing program"))
        self.assertEqual(result, 1)
        restart.assert_called_once()
        self.assertIn("missing program", self.output.getvalue())


class Menu(Workspace):
    def test_main_navigation_returns_directly_from_submenu(self):
        answers = iter(["2", "0"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)), \
                patch.object(app, "live_table", return_value=True), \
                patch.object(app, "ssh_source", return_value=None), \
                patch.object(app, "edit_list") as edit:
            self.assertEqual(app.interactive_menu(), 0)
        edit.assert_called_once_with("blocked_ips")

    def test_whitelist_group_routes_all_categories_and_returns_to_home(self):
        answers = iter(["1", "1", "2", "3", "0", "0"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)), \
                patch.object(app, "live_table", return_value=True), \
                patch.object(app, "ssh_source", return_value=None), \
                patch.object(app, "edit_list") as edit:
            self.assertEqual(app.interactive_menu(), 0)
        self.assertEqual([call.args[0] for call in edit.call_args_list], ["ips", "cidrs", "provinces"])

    def test_province_paging_keeps_global_numbers(self):
        answers = iter(["n", "13 14"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)):
            result = app.province_input()
        self.assertEqual(result.split(), app.PROVINCE_NAMES[12:14])

    def test_delete_ranges_retry_invalid_input_without_losing_page(self):
        items = ["192.0.2.%d" % x for x in range(1, 16)]
        answers = iter(["n", "99", "12-14"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)):
            result = app.select_entries("ips", items)
        self.assertEqual(result, set(items[11:14]))

    def test_cancel_pause_does_not_change_firewall(self):
        answers = iter(["7", "0", "0"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)), \
                patch.object(app, "live_table", return_value=True), \
                patch.object(app, "ssh_source", return_value=None), \
                patch.object(app, "edit_config") as edit:
            self.assertEqual(app.interactive_menu(), 0)
        edit.assert_not_called()

    def test_batch_add_then_delete(self):
        self.install_fake_nft()
        answers = iter(["1", "192.0.2.8, 2001:db8::8", "", "", "2", "1 2", "y", "0"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)), \
                patch.object(app, "ssh_source", return_value=None):
            app.edit_list("ips")
        self.assertEqual(app.load_config()["ips"], [])

    def test_current_session_revocation_requires_confirmation(self):
        candidate = config()
        with patch.object(app, "ssh_source", return_value="192.0.2.8"), \
                patch.object(app, "read_choice", return_value=""):
            self.assertFalse(app.guard_session(candidate))

    def test_other_allow_sources_explain_why_deleted_ip_still_allowed(self):
        cfg = config(cidrs=["198.51.100.0/24"])
        self.assertEqual(app.matching_sources(cfg, "198.51.100.8"), ["网段白名单：198.51.100.0/24"])

    def test_revoke_covered_ip_creates_explicit_deny(self):
        cfg = config(ips=["198.51.100.8"], cidrs=["198.51.100.0/24"])
        result = app.revoke_addresses(cfg, ["198.51.100.8"])
        self.assertEqual(result["ips"], [])
        self.assertEqual(result["blocked_ips"], ["198.51.100.8"])
        self.assertEqual(result["cidrs"], cfg["cidrs"])

    def test_revoke_requires_another_rescue_address(self):
        with self.assertRaises(app.AppError):
            app.revoke_addresses(config(), ["192.0.2.1"])

    def test_revoke_duplicate_rescue_without_silent_readdition(self):
        cfg = config(rescue_ips=["192.0.2.1", "192.0.2.8"], ips=["192.0.2.8"])
        result = app.revoke_addresses(cfg, ["192.0.2.8"])
        self.assertEqual(result["rescue_ips"], ["192.0.2.1"])
        self.assertEqual(result["blocked_ips"], ["192.0.2.8"])

    def test_rescue_network_requires_explicit_adjustment(self):
        with self.assertRaises(app.AppError):
            app.revoke_addresses(config(rescue_ips=["192.0.2.0/24"]), ["192.0.2.8"])

    def test_batch_failure_does_not_save_partial_list(self):
        self.install_fake_nft()
        answers = iter(["1", "192.0.2.8, invalid", "0"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)):
            app.edit_list("ips")
        self.assertEqual(app.load_config()["ips"], [])
        self.assertFalse(self.calls)


class NoteConfig(unittest.TestCase):
    def test_old_configuration_defaults_to_no_notes(self):
        self.assertEqual(app.validate_config({"rescue_ips": ["192.0.2.1"]})["notes"], {})

    def test_notes_roundtrip_and_follow_normalized_entries(self):
        cfg = config(ips=["2001:db8::ABCD"], cidrs=["192.0.2.18/24"], provinces=["广东省"],
                     notes={"ips": {"2001:db8::abcd": '张三 "手机" \\ 备用 #1'},
                            "cidrs": {"192.0.2.18/24": "公司网络"}, "provinces": {"粤": "广东客户"}})
        self.assertEqual(cfg["notes"]["cidrs"], {"192.0.2.0/24": "公司网络"})
        self.assertEqual(cfg["notes"]["provinces"], {"广东": "广东客户"})
        self.assertEqual(tomllib.loads(app.dump_config(cfg)), cfg)

    def test_rejects_invalid_notes_and_conflicting_aliases(self):
        for notes in ([], {"unknown": {}}, {"ips": []}, {"ips": {"192.0.2.8": 5}},
                      {"ips": {"192.0.2.8": "a" * 121}}, {"ips": {"192.0.2.8": "a\nb"}},
                      {"ips": {"192.0.2.8": "\033[31mred"}},
                      {"provinces": {"广东": "one", "粤": "two"}}):
            with self.subTest(notes=notes), self.assertRaises(app.AppError):
                config(ips=["192.0.2.8"], provinces=["广东"], notes=notes)

    def test_removed_entries_drop_notes_without_mutating_input(self):
        cfg = config(ips=["192.0.2.8"], notes={"ips": {"192.0.2.8": "张三"}})
        candidate = copy.deepcopy(cfg)
        candidate["ips"] = []
        self.assertEqual(app.validate_config(candidate)["notes"], {})
        self.assertEqual(cfg["notes"]["ips"]["192.0.2.8"], "张三")
        self.assertEqual(app.revoke_addresses(cfg, ["192.0.2.8"])["notes"], {})


class NoteMenu(Workspace):
    def setUp(self):
        super().setUp()
        self.install_fake_nft()
        fetch = patch.object(app, "fetch_provinces", return_value=set())
        fetch.start()
        self.addCleanup(fetch.stop)

    def edit(self, key, choices):
        with patch.object(app, "read_choice", side_effect=choices), \
                patch.object(app, "ssh_source", return_value=None):
            app.edit_list(key)

    def test_add_notes_for_ip_network_and_province(self):
        for key, entry, canonical in (("ips", "2001:db8::ABCD", "2001:db8::abcd"),
                                      ("cidrs", "192.0.2.18/24", "192.0.2.0/24"),
                                      ("provinces", "粤", "广东")):
            with self.subTest(key=key):
                self.edit(key, ["1", entry, "张三", "0"])
                self.assertEqual(app.load_config()["notes"][key][canonical], "张三")
        self.assertIn("备注", self.output.getvalue())
        self.assertIn("张三", self.output.getvalue())

    def test_batch_notes_can_be_skipped_and_cancelled_without_partial_save(self):
        self.edit("ips", ["1", "192.0.2.8 192.0.2.9", "张三", "0", "0"])
        self.assertEqual(app.load_config()["ips"], [])
        self.assertEqual(app.load_config()["notes"], {})
        self.assertFalse(self.calls)
        self.edit("ips", ["1", "192.0.2.8 192.0.2.9", "张三", "", "0"])
        self.assertEqual(app.load_config()["notes"]["ips"], {"192.0.2.8": "张三"})

    def test_edit_clear_and_rollback_notes_preserve_addresses_and_rules(self):
        self.edit("ips", ["1", "192.0.2.8", "张三", "0"])
        rules = self.rules
        self.edit("ips", ["4", "1", "李四", "0"])
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "李四")
        self.assertEqual(self.rules, rules)
        self.edit("ips", ["4", "1", "-", "0"])
        self.assertEqual(app.load_config()["notes"], {})
        self.assertEqual(app.load_config()["ips"], ["192.0.2.8"])
        app.rollback()
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "李四")
        self.assertEqual(self.rules, rules)

    def test_duplicate_add_preserves_note_and_removal_cleans_it_up(self):
        self.edit("ips", ["1", "192.0.2.8", "张三", "0"])
        self.edit("ips", ["1", "192.0.2.8", "0"])
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "张三")
        self.edit("ips", ["2", "1", "1", "0"])
        self.assertEqual(app.load_config()["notes"], {})

    def test_edit_cancel_keeps_note_and_full_list_shows_it(self):
        self.edit("ips", ["1", "192.0.2.8", "张三", "0"])
        self.edit("ips", ["4", "1", "0", "3", "0", "0"])
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "张三")
        self.assertIn("完整列表", self.output.getvalue())


class PausedConfig(unittest.TestCase):
    def test_old_configuration_enables_every_entry(self):
        cfg = app.validate_config({"rescue_ips": ["192.0.2.1"], "ips": ["192.0.2.8"]})
        self.assertEqual(cfg["paused"], {})
        self.assertIn("192.0.2.8", app.build_allowlist(cfg))

    def test_pause_roundtrip_normalizes_and_preserves_notes(self):
        cfg = config(ips=["2001:db8::ABCD"], cidrs=["192.0.2.18/24"], provinces=["广东省"],
                     notes={"ips": {"2001:db8::abcd": "张三"}},
                     paused={"ips": ["2001:db8::ABCD"], "cidrs": ["192.0.2.9/24"], "provinces": ["粤"]})
        self.assertEqual(cfg["paused"], {"ips": ["2001:db8::abcd"], "cidrs": ["192.0.2.0/24"], "provinces": ["广东"]})
        self.assertEqual(tomllib.loads(app.dump_config(cfg)), cfg)
        self.assertEqual(cfg["notes"]["ips"]["2001:db8::abcd"], "张三")

    def test_invalid_pause_config_rejected(self):
        for paused in ([], {"rescue_ips": ["192.0.2.1"]}, {"blocked_ips": []}, {"ips": "192.0.2.8"},
                       {"ips": [5]}, {"ips": ["invalid"]}, {"provinces": ["不存在"]}):
            with self.subTest(paused=paused), self.assertRaises(app.AppError):
                config(paused=paused)

    def test_paused_entries_do_not_generate_rules_or_download_provinces(self):
        cfg = config(ips=["192.0.2.8", "2001:db8::8"], cidrs=["198.51.100.0/24"], provinces=["广东"],
                     paused={"ips": ["192.0.2.8", "2001:db8::8"], "cidrs": ["198.51.100.0/24"], "provinces": ["广东"]})
        with patch.object(app, "fetch_provinces") as fetch:
            self.assertEqual(app.build_allowlist(cfg, force_refresh=True), {"192.0.2.1"})
            self.assertEqual(app.prepare(cfg), app.prepare(config()))
            fetch.assert_not_called()

    def test_only_enabled_provinces_are_requested(self):
        cfg = config(provinces=["广东", "北京"], paused={"provinces": ["广东"]})
        with patch.object(app, "fetch_provinces", return_value={"198.51.100.0/24"}) as fetch:
            self.assertEqual(app.build_allowlist(cfg), {"192.0.2.1", "198.51.100.0/24"})
        self.assertEqual(fetch.call_args.args[0], ["北京"])

    def test_removing_entry_cleans_pause_and_notes(self):
        cfg = config(ips=["192.0.2.8"], notes={"ips": {"192.0.2.8": "张三"}}, paused={"ips": ["192.0.2.8"]})
        result = app.revoke_addresses(cfg, ["192.0.2.8"])
        self.assertEqual(result["paused"], {})
        self.assertEqual(result["notes"], {})


class PausedMenu(Workspace):
    def setUp(self):
        super().setUp()
        self.install_fake_nft()
        app.atomic_write(Path(app.CACHE_DIR) / "440000.txt", "198.51.100.0/24\n")

    def edit(self, key, choices, source=None):
        with patch.object(app, "read_choice", side_effect=choices), patch.object(app, "ssh_source", return_value=source):
            app.edit_list(key)

    def test_pause_resume_all_types_keep_entry_and_note(self):
        for key, entry in (("ips", "192.0.2.8"), ("cidrs", "198.51.100.0/24"), ("provinces", "广东")):
            with self.subTest(key=key):
                cfg = config(**{key: [entry]}, notes={key: {entry: "张三"}})
                app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
                app.apply_once()
                enabled_rules = self.rules
                self.edit(key, ["5", "1", "1", "0"])
                paused = app.load_config()
                self.assertEqual(paused[key], [entry])
                self.assertEqual(paused["notes"][key][entry], "张三")
                self.assertEqual(paused["paused"][key], [entry])
                self.assertNotEqual(self.rules, enabled_rules)
                self.edit(key, ["6", "1", "1", "0"])
                self.assertEqual(app.load_config(), cfg)
                self.assertEqual(self.rules, enabled_rules)

    def test_pause_can_be_cancelled_and_batch_selected(self):
        cfg = config(ips=["192.0.2.8", "192.0.2.9"])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        self.edit("ips", ["5", "1-2", "0", "0"])
        self.assertEqual(app.load_config(), cfg)
        self.assertFalse(self.calls)
        self.edit("ips", ["5", "1-2", "1", "0"])
        self.assertEqual(app.load_config()["paused"]["ips"], cfg["ips"])
        self.edit("ips", ["6", "2", "1", "0"])
        self.assertEqual(app.load_config()["paused"]["ips"], ["192.0.2.8"])

    def test_pause_ssh_source_requires_extra_confirmation(self):
        cfg = config(ips=["192.0.2.8"])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        self.edit("ips", ["5", "1", "1", "0", "0"], source="192.0.2.8")
        self.assertEqual(app.load_config(), cfg)
        self.assertFalse(self.calls)
        self.assertIn("将失去权限", self.output.getvalue())

    def test_paused_sources_are_ignored_but_other_coverage_remains(self):
        cfg = config(ips=["198.51.100.8"], cidrs=["198.51.100.0/24"], provinces=["广东"],
                     paused={"ips": ["198.51.100.8"], "provinces": ["广东"]})
        self.assertEqual(app.matching_sources(cfg, "198.51.100.8"), ["网段白名单：198.51.100.0/24"])
        cfg["paused"]["cidrs"] = cfg["cidrs"]
        self.assertEqual(app.matching_sources(cfg, "198.51.100.8"), [])

    def test_pause_persists_through_boot_and_rollback_restores_enabled_state(self):
        cfg = config(ips=["192.0.2.8"], notes={"ips": {"192.0.2.8": "张三"}})
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        app.apply_once()
        enabled_rules = self.rules
        self.edit("ips", ["5", "1", "1", "0"])
        paused_rules = self.rules
        self.rules = ""
        app.boot()
        self.assertEqual(self.rules, paused_rules)
        app.rollback()
        self.assertEqual(app.load_config(), cfg)
        self.assertEqual(self.rules, enabled_rules)

    def test_duplicate_add_and_note_edit_do_not_resume_entry(self):
        cfg = config(ips=["192.0.2.8"], notes={"ips": {"192.0.2.8": "张三"}}, paused={"ips": ["192.0.2.8"]})
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        self.edit("ips", ["1", "192.0.2.8", "4", "1", "李四", "0"])
        self.assertEqual(app.load_config()["paused"], cfg["paused"])
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "李四")

    def test_failed_pause_preserves_saved_state(self):
        cfg = config(ips=["192.0.2.8"])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        app.apply_once()
        previous_state = app.read_state()
        with patch.object(app, "nft", side_effect=app.AppError("rejected rules")):
            self.edit("ips", ["5", "1", "1", "0"])
        self.assertEqual(app.load_config(), cfg)
        self.assertEqual(app.read_state(), previous_state)


class FirewallSynchronization(Workspace):
    def setUp(self):
        super().setUp()
        self.install_fake_nft()
        live = patch.object(app, "live_table", side_effect=lambda: "\ntable inet vps_wl {" in self.rules)
        live.start()
        self.addCleanup(live.stop)

    def menu(self, choices):
        with patch.object(app, "read_choice", side_effect=choices), patch.object(app, "ssh_source", return_value=None):
            return app.interactive_menu()

    def test_enable_survives_exit_and_fresh_menu(self):
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(enabled=False)))
        self.assertEqual(self.menu(["7", "1", "0"]), 0)
        self.assertTrue(app.load_config()["enabled"])
        self.assertTrue(app.live_table())
        self.output.seek(0)
        self.output.truncate()
        self.assertEqual(self.menu(["0"]), 0)
        self.assertIn("防火墙：开启", self.output.getvalue())
        self.assertNotIn("防火墙：关闭", self.output.getvalue())

    def test_mismatch_is_not_reported_as_intentional_shutdown(self):
        self.assertEqual(app.firewall_label(config(), False), "未生效")
        self.assertEqual(app.firewall_label(config(enabled=False), True), "未关闭")
        self.assertEqual(app.protection_action(config(), False), "恢复防护")
        self.assertIn("设置开启", app.protection_status(config(), False))

    def test_menu_repairs_missing_rules_without_turning_saved_switch_off(self):
        app.apply_once()
        self.rules = app.render_rules([], enabled=False)
        self.assertEqual(self.menu(["7", "1", "0"]), 0)
        self.assertTrue(app.load_config()["enabled"])
        self.assertTrue(app.live_table())
        self.assertIn("恢复防护", self.output.getvalue())

    def test_menu_removes_residual_rules_without_turning_saved_switch_on(self):
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(enabled=False)))
        self.rules = app.prepare(config())
        self.assertEqual(self.menu(["7", "1", "0"]), 0)
        self.assertFalse(app.load_config()["enabled"])
        self.assertFalse(app.live_table())

    def test_stable_daemon_does_not_apply_every_poll(self):
        app.apply_once()
        self.calls.clear()
        with patch.object(app.time, "sleep", side_effect=[None, None, SystemExit]), \
                patch.object(app, "apply_once") as apply:
            with self.assertRaises(SystemExit):
                app.daemon()
        apply.assert_not_called()
        self.assertFalse(self.calls)

    def test_missing_rules_restore_snapshot_once_without_download_or_history_change(self):
        app.apply_once()
        previous_state = app.read_state()
        good_rules = self.rules
        self.rules = app.render_rules([], enabled=False)
        self.calls.clear()
        with patch.object(app.time, "sleep", side_effect=[None, None, SystemExit]), \
                patch.object(app, "prepare", side_effect=AssertionError("must restore exact snapshot")):
            with self.assertRaises(SystemExit):
                app.daemon()
        self.assertEqual(self.rules, good_rules)
        self.assertEqual(app.read_state(), previous_state)
        self.assertEqual(self.calls, [(good_rules, True), (good_rules, False)])
        self.assertIn("旧版服务", self.output.getvalue())

    def test_disabled_snapshot_removes_residual_rules(self):
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(enabled=False)))
        app.apply_once()
        previous_state = app.read_state()
        self.rules = app.prepare(config())
        with patch.object(app.time, "sleep", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                app.daemon()
        self.assertFalse(app.live_table())
        self.assertEqual(app.read_state(), previous_state)

    def test_no_active_provinces_does_not_trigger_periodic_rule_replacement(self):
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(province_refresh=1)))
        app.apply_once()
        with patch.object(app.time, "monotonic", side_effect=[0, 100, 200, 300, 400]), \
                patch.object(app.time, "sleep", side_effect=[None, SystemExit]), \
                patch.object(app, "apply_once") as apply:
            with self.assertRaises(SystemExit):
                app.daemon()
        apply.assert_not_called()

    def test_status_reports_legacy_service_conflict(self):
        app.apply_once()
        with patch.object(app, "run", return_value=SimpleNamespace(stdout="active\n", stderr="", returncode=0)):
            app.status()
        self.assertIn("旧版 vps-whitelist 仍在运行", self.output.getvalue())
        self.assertIn("保存的开关：开启", self.output.getvalue())
        self.assertIn("实际规则表：存在", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
