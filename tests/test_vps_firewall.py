"""Cross-platform regression checks; never call the host firewall."""
import copy
from contextlib import nullcontext, redirect_stdout
import io
import json
import os
import re
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
        for changes in ({"ips": ["not-an-ip"]}, {"ips": ["192.0.2.0/24"]},
                        {"enabled": "false"}, {"watch_interval": 0}, {"province_refresh": -1},
                        {"provinces": ["不存在"]}, {"ips": "192.0.2.2"},
                        {"rescue_ips": []}, {"blocked_ips": ["192.0.2.1"]},
                        {"province_source_base": "file:///etc/passwd"}, {"extra": 1}):
            with self.subTest(changes=changes), self.assertRaises(app.AppError):
                config(**changes)

    def test_overlapping_networks_collapse_and_ipv6_input_is_rejected(self):
        values = ["192.0.2.18/24", "192.0.2.1", "198.51.100.0/25", "198.51.100.128/25"]
        self.assertEqual(app.collapse(values), ["192.0.2.0/24", "198.51.100.0/24"])
        self.assertEqual(app.norm(" 192.0.2.18/24 "), "192.0.2.0/24")
        for value in ("2001:db8::FFFF", "2001:db8::/64", "::ffff:192.0.2.1", "::/0"):
            with self.subTest(value=value), self.assertRaisesRegex(app.AppError, "只过滤 IPv4"):
                app.norm(value)

    def test_removed_ssh_ip_is_not_implicitly_added(self):
        with patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.9 1234 192.0.2.2 2222"}):
            self.assertEqual(app.build_allowlist(config()), {"192.0.2.1"})

    def test_ssh_source_reports_custom_port_and_ipv6_logins(self):
        for connection, source in (("192.0.2.9 1234 192.0.2.2 22000", "192.0.2.9"),
                                   ("2001:db8::9 1234 2001:db8::2 22000", "2001:db8::9"),
                                   ("::ffff:192.0.2.9 1234 ::ffff:192.0.2.2 22", "192.0.2.9")):
            with self.subTest(connection=connection), patch.dict(os.environ, {"SSH_CONNECTION": connection}):
                self.assertEqual(app.ssh_source(), source)

    def test_inbound_established_no_longer_bypasses_membership(self):
        rules = app.render_rules(["192.0.2.1"])
        self.assertNotIn("        ct state established,related accept", rules)
        self.assertIn("ct direction reply ct state established,related accept", rules)
        self.assertIn("ct status dnat ct direction original jump published", rules)

    def test_rules_only_filter_ipv4_and_leave_ipv6_untouched(self):
        for mode in app.PING_MODES:
            for protect_dnat in (True, False):
                with self.subTest(mode=mode, protect_dnat=protect_dnat):
                    rules = app.render_rules(["192.0.2.1"], mode, ["198.51.100.7"], protect_dnat=protect_dnat)
                    # ip 族的表只会看到 IPv4；表内不得再出现任何 IPv6 匹配。
                    self.assertIn("\ntable ip vps_wl {\n", rules)
                    self.assertNotIn("table inet vps_wl {", rules)
                    for token in ("ip6", "icmpv6", "ipv6", "allow6", "blocked6", "nd-neighbor", "nfproto"):
                        self.assertNotIn(token, rules)
                    self.assertLess(rules.index("ip saddr @blocked4 counter drop"),
                                    rules.index("ip saddr @allow4 accept"))

    def test_explicit_deny_precedes_allow_in_both_chains(self):
        rules = app.render_rules(["192.0.2.0/24"], blocked_ips=["192.0.2.7"])
        for chain in ("chain input {", "chain published {"):
            body = rules[rules.index(chain):]
            self.assertLess(body.index("ip saddr @blocked4 counter drop"), body.index("ip saddr @allow4 accept"))

    def test_disabled_rules_only_remove_own_table(self):
        rules = app.render_rules([], enabled=False)
        # 同一事务里也清掉 1.2 及更早版本的 inet 表。
        self.assertEqual(rules, "add table inet vps_wl\ndelete table inet vps_wl\nadd table ip vps_wl\ndelete table ip vps_wl\n")
        self.assertNotIn("flush ruleset", rules)

    def test_rule_replacement_and_disable_are_single_atomic_nft_commands(self):
        for rules in (app.render_rules(["192.0.2.1"]), app.render_rules([], enabled=False)):
            with patch.object(app, "run", return_value=SimpleNamespace(returncode=0)) as run:
                app.nft(rules)
                run.assert_called_once_with(["nft", "-f", "-"], rules)
                self.assertTrue(rules.startswith("add table inet vps_wl\ndelete table inet vps_wl\nadd table ip vps_wl\ndelete table ip vps_wl\n"))

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
        with patch.object(app, "ssh_source", return_value="192.0.2.9"):
            app.initialize("192.0.2.99")
        self.assertEqual(app.load_config()["rescue_ips"], ["192.0.2.99", "192.0.2.9"])

    def test_first_install_never_saves_ipv6_management_address(self):
        Path(app.CONFIG_PATH).unlink()
        with patch.object(app, "ssh_source", return_value="2001:db8::9"):
            with patch.object(app.sys.stdin, "isatty", return_value=False), \
                    self.assertRaisesRegex(app.AppError, "IPv4 管理 IP"):
                app.initialize("")
            with self.assertRaisesRegex(app.AppError, "只过滤 IPv4"):
                app.initialize("192.0.2.99,2001:db8::5")
            self.assertFalse(Path(app.CONFIG_PATH).exists())
            app.initialize("192.0.2.99")
        self.assertEqual(app.load_config()["rescue_ips"], ["192.0.2.99"])
        self.assertIn("通过 IPv6 登录", self.output.getvalue())

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
        for choice in ("1", "2"):
            for answer in ("0", ""):
                with self.subTest(choice=choice, answer=answer):
                    result, command, restart = self.run_menu(["9", choice, answer, "0", "0"])
                    self.assertEqual(result, 0)
                    command.assert_not_called()
                    restart.assert_not_called()

    def test_successful_update_replaces_menu_with_installed_program(self):
        result, command, restart = self.run_menu(["9", "1", "1"])
        self.assertEqual(result, 0)
        command.assert_called_once_with([app.sys.executable,
                                         str(Path(app.__file__).with_name("github_install.py"))])
        restart.assert_called_once_with(app.sys.executable,
                                        [app.sys.executable, "/opt/vps-firewall/vps_firewall.py", "menu"])

    def test_successful_uninstall_exits_without_reading_deleted_config(self):
        result, command, restart = self.run_menu(["9", "2", "1"])
        self.assertEqual(result, 0)
        command.assert_called_once_with(["bash", str(Path(app.__file__).with_name("uninstall.sh")), "--yes"])
        restart.assert_not_called()

    def test_failed_update_and_uninstall_exits_without_restart(self):
        for choice in ("1", "2"):
            with self.subTest(choice=choice):
                result, command, restart = self.run_menu(["9", choice, "1"], returncode=1)
                self.assertEqual(result, 1)
                command.assert_called_once()
                restart.assert_not_called()
        self.assertIn("未完成", self.output.getvalue())

    def test_failed_menu_restart_does_not_continue_using_old_code(self):
        result, command, restart = self.run_menu(["9", "1", "1"], restart_error=OSError("missing program"))
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

    def test_province_grid_accepts_numbers_and_names_on_one_page(self):
        answers = iter(["99", "13 14 广东"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)):
            result = app.province_input()
        self.assertEqual(result.split(), app.PROVINCE_NAMES[12:14] + ["广东"])
        self.assertIn("未识别省份", self.output.getvalue())

    def test_delete_ranges_retry_invalid_input_without_losing_page(self):
        items = ["192.0.2.%d" % x for x in range(1, 16)]
        answers = iter(["n", "99", "12-14"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)):
            result = app.select_entries("ips", items)
        self.assertEqual(result, items[11:14])

    def test_cancel_pause_does_not_change_firewall(self):
        answers = iter(["4", "0", "0"])
        with patch.object(app, "read_choice", side_effect=lambda _: next(answers)), \
                patch.object(app, "live_table", return_value=True), \
                patch.object(app, "ssh_source", return_value=None), \
                patch.object(app, "edit_config") as edit:
            self.assertEqual(app.interactive_menu(), 0)
        edit.assert_not_called()

    def test_batch_add_then_delete(self):
        self.install_fake_nft()
        answers = iter(["1", "192.0.2.8, 192.0.2.9", "", "", "2", "1 2", "4", "y", "0"])
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


class EntryManagement(Workspace):
    def setUp(self):
        super().setUp()
        self.install_fake_nft()

    def edit(self, key, choices):
        with patch.object(app, "read_choice", side_effect=choices), \
                patch.object(app, "ssh_source", return_value=None):
            app.edit_list(key)

    def test_list_page_offers_only_add_and_manage(self):
        self.edit("ips", ["0"])
        output = self.output.getvalue()
        self.assertIn("1  添加", output)
        self.assertIn("2  管理条目", output)
        for removed in ("修改备注", "暂停条目", "启用条目", "查看完整列表"):
            self.assertNotIn(removed, output)

    def test_manage_keeps_selection_numbers_and_returns_to_list(self):
        cfg = config(ips=["192.0.2.%d" % x for x in range(1, 16)])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        # 翻到第 2 页选中第 14 项，暂停后回到列表，再返回
        self.edit("ips", ["2", "n", "14", "2", "1", "0", "0"])
        self.assertEqual(app.load_config()["paused"]["ips"], ["192.0.2.14"])
        self.assertIn("已选择 1 项", self.output.getvalue())

    def test_blocked_and_rescue_selection_goes_straight_to_confirmation(self):
        cfg = config(rescue_ips=["192.0.2.1", "192.0.2.2"], blocked_ips=["198.51.100.7"])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        self.edit("blocked_ips", ["2", "1", "1", "0"])
        self.assertEqual(app.load_config()["blocked_ips"], [])
        self.edit("rescue_ips", ["2", "2", "1", "0", "0"])
        self.assertEqual(app.load_config()["rescue_ips"], ["192.0.2.1"])
        self.assertNotIn("从名单中删除，备注一并清除", self.output.getvalue())

    def test_empty_list_manage_reports_instead_of_opening(self):
        with patch.object(app, "select_entries") as select:
            self.edit("ips", ["2", "0"])
        select.assert_not_called()
        self.assertIn("列表为空", self.output.getvalue())


class NoteConfig(unittest.TestCase):
    def test_old_configuration_defaults_to_no_notes(self):
        self.assertEqual(app.validate_config({"rescue_ips": ["192.0.2.1"]})["notes"], {})

    def test_notes_roundtrip_and_follow_normalized_entries(self):
        cfg = config(ips=["192.0.2.8"], cidrs=["192.0.2.18/24"], provinces=["广东省"],
                     notes={"ips": {" 192.0.2.8": '张三 "手机" \\ 备用 #1'},
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
        for key, entry, canonical in (("ips", "192.0.2.8", "192.0.2.8"),
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
        self.edit("ips", ["2", "1", "1", "李四", "0", "0"])
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "李四")
        self.assertEqual(self.rules, rules)
        self.edit("ips", ["2", "1", "1", "-", "0", "0"])
        self.assertEqual(app.load_config()["notes"], {})
        self.assertEqual(app.load_config()["ips"], ["192.0.2.8"])
        app.rollback()
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "李四")
        self.assertEqual(self.rules, rules)

    def test_duplicate_add_preserves_note_and_removal_cleans_it_up(self):
        self.edit("ips", ["1", "192.0.2.8", "张三", "0"])
        self.edit("ips", ["1", "192.0.2.8", "0"])
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "张三")
        self.edit("ips", ["2", "1", "4", "1", "0"])
        self.assertEqual(app.load_config()["notes"], {})

    def test_edit_cancel_keeps_note_and_full_list_shows_it(self):
        self.edit("ips", ["1", "192.0.2.8", "张三", "0"])
        self.edit("ips", ["2", "1", "1", "0", "0", "0"])
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "张三")
        self.assertIn("管理条目", self.output.getvalue())
        self.assertIn("已取消修改备注", self.output.getvalue())


class PausedConfig(unittest.TestCase):
    def test_old_configuration_enables_every_entry(self):
        cfg = app.validate_config({"rescue_ips": ["192.0.2.1"], "ips": ["192.0.2.8"]})
        self.assertEqual(cfg["paused"], {})
        self.assertIn("192.0.2.8", app.build_allowlist(cfg))

    def test_pause_roundtrip_normalizes_and_preserves_notes(self):
        cfg = config(ips=["192.0.2.8"], cidrs=["192.0.2.18/24"], provinces=["广东省"],
                     notes={"ips": {"192.0.2.8": "张三"}},
                     paused={"ips": [" 192.0.2.8"], "cidrs": ["192.0.2.9/24"], "provinces": ["粤"]})
        self.assertEqual(cfg["paused"], {"ips": ["192.0.2.8"], "cidrs": ["192.0.2.0/24"], "provinces": ["广东"]})
        self.assertEqual(tomllib.loads(app.dump_config(cfg)), cfg)
        self.assertEqual(cfg["notes"]["ips"]["192.0.2.8"], "张三")

    def test_invalid_pause_config_rejected(self):
        for paused in ([], {"rescue_ips": ["192.0.2.1"]}, {"blocked_ips": []}, {"ips": "192.0.2.8"},
                       {"ips": [5]}, {"ips": ["invalid"]}, {"provinces": ["不存在"]}):
            with self.subTest(paused=paused), self.assertRaises(app.AppError):
                config(paused=paused)

    def test_paused_entries_do_not_generate_rules_or_download_provinces(self):
        cfg = config(ips=["192.0.2.8", "192.0.2.9"], cidrs=["198.51.100.0/24"], provinces=["广东"],
                     paused={"ips": ["192.0.2.8", "192.0.2.9"], "cidrs": ["198.51.100.0/24"], "provinces": ["广东"]})
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
                self.edit(key, ["2", "1", "2", "1", "0", "0"])
                paused = app.load_config()
                self.assertEqual(paused[key], [entry])
                self.assertEqual(paused["notes"][key][entry], "张三")
                self.assertEqual(paused["paused"][key], [entry])
                self.assertNotEqual(self.rules, enabled_rules)
                self.edit(key, ["2", "1", "3", "1", "0", "0"])
                self.assertEqual(app.load_config(), cfg)
                self.assertEqual(self.rules, enabled_rules)

    def test_pause_can_be_cancelled_and_batch_selected(self):
        cfg = config(ips=["192.0.2.8", "192.0.2.9"])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        self.edit("ips", ["2", "1-2", "2", "0", "0", "0"])
        self.assertEqual(app.load_config(), cfg)
        self.assertFalse(self.calls)
        self.edit("ips", ["2", "1-2", "2", "1", "0", "0"])
        self.assertEqual(app.load_config()["paused"]["ips"], cfg["ips"])
        self.edit("ips", ["2", "2", "3", "1", "0", "0"])
        self.assertEqual(app.load_config()["paused"]["ips"], ["192.0.2.8"])

    def test_pause_ssh_source_requires_extra_confirmation(self):
        cfg = config(ips=["192.0.2.8"])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        self.edit("ips", ["2", "1", "2", "1", "0", "0", "0"], source="192.0.2.8")
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
        self.edit("ips", ["2", "1", "2", "1", "0", "0"])
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
        self.edit("ips", ["1", "192.0.2.8", "2", "1", "1", "李四", "0", "0"])
        self.assertEqual(app.load_config()["paused"], cfg["paused"])
        self.assertEqual(app.load_config()["notes"]["ips"]["192.0.2.8"], "李四")

    def test_failed_pause_preserves_saved_state(self):
        cfg = config(ips=["192.0.2.8"])
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        app.apply_once()
        previous_state = app.read_state()
        with patch.object(app, "nft", side_effect=app.AppError("rejected rules")):
            self.edit("ips", ["2", "1", "2", "1", "0", "0"])
        self.assertEqual(app.load_config(), cfg)
        self.assertEqual(app.read_state(), previous_state)


class FirewallSynchronization(Workspace):
    def setUp(self):
        super().setUp()
        self.install_fake_nft()
        live = patch.object(app, "live_table", side_effect=lambda: "\ntable ip vps_wl {" in self.rules)
        live.start()
        self.addCleanup(live.stop)

    def menu(self, choices):
        with patch.object(app, "read_choice", side_effect=choices), patch.object(app, "ssh_source", return_value=None):
            return app.interactive_menu()

    def test_enable_survives_exit_and_fresh_menu(self):
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(enabled=False)))
        self.assertEqual(self.menu(["4", "1", "0"]), 0)
        self.assertTrue(app.load_config()["enabled"])
        self.assertTrue(app.live_table())
        self.output.seek(0)
        self.output.truncate()
        self.assertEqual(self.menu(["0"]), 0)
        self.assertIn("● 防护中", self.output.getvalue())
        self.assertNotIn("○ 已暂停", self.output.getvalue())

    def test_mismatch_is_not_reported_as_intentional_shutdown(self):
        self.assertEqual(app.firewall_label(config(), False), "未生效")
        self.assertEqual(app.firewall_label(config(enabled=False), True), "未关闭")
        self.assertEqual(app.protection_action(config(), False), "恢复防护")
        self.assertIn("设置开启", app.protection_status(config(), False))

    def test_menu_repairs_missing_rules_without_turning_saved_switch_off(self):
        app.apply_once()
        self.rules = app.render_rules([], enabled=False)
        self.assertEqual(self.menu(["4", "1", "0"]), 0)
        self.assertTrue(app.load_config()["enabled"])
        self.assertTrue(app.live_table())
        self.assertIn("恢复防护", self.output.getvalue())

    def test_menu_removes_residual_rules_without_turning_saved_switch_on(self):
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(enabled=False)))
        self.rules = app.prepare(config())
        self.assertEqual(self.menu(["4", "1", "0"]), 0)
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
        self.assertRegex(self.output.getvalue(), r"保存的开关\s+开启")
        self.assertRegex(self.output.getvalue(), r"实际规则表\s+存在")


class LocalProvincePackages(Workspace):
    def test_missing_cache_directory_stays_absent(self):
        self.assertEqual(app.local_province_packages(), [])
        self.assertFalse(Path(app.CACHE_DIR).exists())
        with patch.object(app, "read_choice", side_effect=["0"]):
            app.view_local_province_packages()
        self.assertIn("暂无本地省份包", self.output.getvalue())
        self.assertFalse(Path(app.CACHE_DIR).exists())

    def test_lists_real_cache_including_unselected_and_invalid_packages(self):
        cache = Path(app.CACHE_DIR)
        app.atomic_write(cache / "440000.txt", "192.0.2.0/24\n192.0.2.0/24\n198.51.100.0/24\n")
        app.atomic_write(cache / "110000.txt", "not a network")
        app.atomic_write(cache / "README.txt", "ignored")
        (cache / "310000.txt").mkdir()
        os.utime(cache / "440000.txt", (1234567890, 1234567890))
        packages = {package["name"]: package for package in app.local_province_packages()}
        self.assertEqual(set(packages), {"广东", "北京"})
        self.assertEqual(packages["广东"]["networks"], 2)
        self.assertEqual(packages["广东"]["updated_at"], 1234567890)
        self.assertEqual(packages["广东"]["error"], "")
        self.assertIsNone(packages["北京"]["networks"])
        self.assertTrue(packages["北京"]["error"])

    def test_view_reports_usage_without_download_or_mutation(self):
        cache = Path(app.CACHE_DIR)
        for code in ("110000", "440000", "310000"):
            app.atomic_write(cache / (code + ".txt"), "192.0.2.0/24\n")
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(provinces=["北京", "广东"], paused={"provinces": ["广东"]})))
        before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in cache.iterdir()}
        with patch.object(app, "read_choice", side_effect=["0"]), \
                patch.object(app, "fetch_provinces", side_effect=AssertionError("must not download")), \
                patch.object(app, "nft", side_effect=AssertionError("must not modify rules")), \
                patch.object(app, "atomic_write", side_effect=AssertionError("must not write files")):
            app.view_local_province_packages()
        self.assertEqual(before, {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in cache.iterdir()})
        output = self.output.getvalue()
        for name, state in (("北京", "启用"), ("广东", "暂停"), ("上海", "未选用")):
            self.assertTrue(any(name in line and state in line for line in output.splitlines()), output)

    def test_paging_keeps_global_numbers_and_returns_to_maintenance(self):
        for name in app.PROVINCE_NAMES[:13]:
            app.atomic_write(Path(app.CACHE_DIR) / (app.resolve_province_code(name) + ".txt"), "192.0.2.0/24\n")
        with patch.object(app, "read_choice", side_effect=["3", "n", "0", "0"]):
            app.maintenance_menu()
        output = self.output.getvalue()
        self.assertIn("第 2 / 2 页", output)
        self.assertTrue(any("13" in line and app.PROVINCE_NAMES[12] in line for line in output.splitlines()))


class PublicPing(Workspace):
    ACCEPT = ("icmp type echo-request accept",)
    DROP = ("icmp type echo-request counter drop",)

    def setUp(self):
        super().setUp()
        self.install_fake_nft()

    def home(self, choices):
        with patch.object(app, "read_choice", side_effect=choices), \
                patch.object(app, "live_table", return_value=True), \
                patch.object(app, "ssh_source", return_value=None):
            return app.interactive_menu()

    def assert_ping_rules(self, mode):
        for rule in self.ACCEPT:
            (self.assertIn if mode == "all" else self.assertNotIn)(rule, self.rules)
        for rule in self.DROP:
            (self.assertIn if mode == "off" else self.assertNotIn)(rule, self.rules)

    def test_default_is_whitelist_only_and_rules_follow(self):
        app.apply_once()
        self.assertEqual(app.load_config()["ping_mode"], "whitelist")
        self.assert_ping_rules("whitelist")

    def test_off_drops_echo_before_allow_set(self):
        rules = app.render_rules(["192.0.2.1"], ping_mode="off")
        order = [rules.index(x) for x in ('iifname "lo" accept', "ip saddr @blocked4 counter drop",
                                           "icmp type echo-request counter drop", "ip saddr @allow4 accept")]
        self.assertEqual(order, sorted(order))
        all_rules = app.render_rules(["192.0.2.1"], ping_mode="all")
        self.assertLess(all_rules.index("ip saddr @blocked4 counter drop"),
                        all_rules.index("icmp type echo-request accept"))
        with self.assertRaises(app.AppError):
            app.render_rules([], ping_mode="on")

    def test_invalid_mode_rejected(self):
        for value in ("on", "", True, None, "OFF"):
            with self.subTest(value=value), self.assertRaises(app.AppError):
                config(ping_mode=value)

    def test_legacy_allow_ping_is_converted(self):
        for legacy, mode in ((True, "all"), (False, "whitelist")):
            with self.subTest(legacy=legacy):
                raw = {"rescue_ips": ["192.0.2.1"], "allow_ping": legacy}
                app.atomic_write(app.CONFIG_PATH, "rescue_ips = [\"192.0.2.1\"]\nallow_ping = %s\n"
                                 % str(legacy).lower())
                cfg = app.load_config()
                self.assertEqual(cfg["ping_mode"], mode)
                self.assertNotIn("allow_ping", cfg)
                self.assertEqual(app.validate_config(raw), cfg)
                self.assertIn('ping_mode = "%s"' % mode, app.dump_config(cfg))
                self.assertNotIn("allow_ping", app.dump_config(cfg))
        for raw in ({"allow_ping": "yes"}, {"allow_ping": True, "ping_mode": "all"}):
            with self.subTest(raw=raw), self.assertRaises(app.AppError):
                app.validate_config(dict(raw, rescue_ips=["192.0.2.1"]))

    def test_legacy_state_still_supports_ip_check(self):
        cfg = config(ips=["192.0.2.8"])
        legacy = dict(cfg)
        legacy.pop("ping_mode")
        legacy["allow_ping"] = True
        state = {"current": {"config": legacy, "rules": app.render_rules(["192.0.2.1", "192.0.2.8"], "all"),
                             "applied_at": time.time()}}
        app.atomic_write(app.STATE_PATH, json.dumps(state))
        with patch.object(app, "live_table", return_value=True):
            report = app.address_report("198.51.100.9")
        self.assertIn("可以 ping", "\n".join(report[0][1]))
        # 升级后旧记录与换算后的配置视为一致：不提示未同步，也不会顶掉回滚备份。
        self.assertEqual(app.read_state()["current"]["config"], dict(cfg, ping_mode="all"))

    def test_home_menu_selects_each_mode_and_saves(self):
        for number, mode, text in (("1", "off", "全部禁止"), ("3", "all", "所有人"), ("2", "whitelist", "仅白名单")):
            with self.subTest(mode=mode):
                self.output.seek(0)
                self.output.truncate()
                self.assertEqual(self.home(["5", number, "0"]), 0)
                self.assertEqual(app.load_config()["ping_mode"], mode)
                self.assert_ping_rules(mode)
                self.assertIn("已保存并生效：公网 Ping：" + text, self.output.getvalue())

    def test_ping_page_cancel_and_invalid_input_change_nothing(self):
        before = app.load_config()
        self.assertEqual(self.home(["5", "9", "0", "0"]), 0)
        self.assertIn("请输入 0 到 3 之间的编号", self.output.getvalue())
        self.assertEqual(app.load_config(), before)
        self.assertEqual(self.calls, [])

    def test_ping_command_switches_without_menu(self):
        app.ping_command("off")
        self.assertEqual(app.load_config()["ping_mode"], "off")
        self.assert_ping_rules("off")
        app.ping_command("on")
        self.assertEqual(app.load_config()["ping_mode"], "all")
        self.assert_ping_rules("all")
        calls = len(self.calls)
        app.ping_command("all")
        self.assertEqual(len(self.calls), calls)
        app.ping_command("whitelist")
        self.assertEqual(app.load_config()["ping_mode"], "whitelist")
        app.ping_command()
        self.assertIn("公网 Ping：仅白名单", self.output.getvalue())

    def test_ip_check_reports_ping_per_mode(self):
        for mode, allowed_ip, other_ip in (("off", False, False), ("whitelist", True, False), ("all", True, True)):
            with self.subTest(mode=mode):
                app.edit_config(app.load_config(), config(ips=["192.0.2.8"], ping_mode=mode))
                with patch.object(app, "live_table", return_value=True):
                    for address, expected in (("192.0.2.8", allowed_ip), ("198.51.100.9", other_ip)):
                        text = "\n".join(app.address_report(address)[0][1])
                        self.assertIn("可以 ping" if expected else "不能 ping", text)


class IPv4Only(Workspace):
    """1.3.0 起只过滤 IPv4：旧配置 / 旧记录中的 IPv6 内容自动清除，IPv6 流量不经过本程序。"""

    LEGACY_CONFIG = """enabled = true
rescue_ips = ["192.0.2.1", "2001:db8::1"]
provinces = []
cidrs = ["198.51.100.0/24", "2001:db8:1::/48"]
ips = ["192.0.2.8", "2001:db8::8"]
blocked_ips = ["203.0.113.7", "2001:db8::7"]
allow_ping = false
allow_all_ipv6 = true
protect_dnat = true

[paused]
ips = ["2001:db8::8"]
cidrs = ["2001:db8:1::/48"]

[notes.ips]
"192.0.2.8" = "张三"
"2001:db8::8" = "李四"
"""
    LEGACY_RULES = ("add table inet vps_wl\ndelete table inet vps_wl\ntable inet vps_wl {\n"
                    "    set allow4 {\n        type ipv4_addr\n        flags interval\n"
                    "        elements = { 192.0.2.1 }\n    }\n"
                    "    chain input {\n        ip6 saddr @allow6 accept\n    }\n}\n")

    def setUp(self):
        super().setUp()
        self.install_fake_nft()

    def legacy_record(self, **changes):
        cfg = dict(config(**changes))
        cfg.pop("ping_mode")
        cfg.update(allow_ping=False, allow_all_ipv6=False)
        return {"config": cfg, "rules": self.LEGACY_RULES, "applied_at": time.time()}

    def test_legacy_ipv6_content_is_ignored_and_reported(self):
        app.atomic_write(app.CONFIG_PATH, self.LEGACY_CONFIG)
        cfg = app.load_config()
        self.assertEqual(cfg, config(cidrs=["198.51.100.0/24"], ips=["192.0.2.8"], blocked_ips=["203.0.113.7"],
                                     notes={"ips": {"192.0.2.8": "张三"}}))
        self.assertNotIn("allow_all_ipv6", cfg)
        self.assertEqual(app.ipv6_leftovers(), [
            "IPv6 全部放行开关", "直通 IP（管理地址） 2001:db8::1", "网段白名单 2001:db8:1::/48",
            "IP 白名单 2001:db8::8", "禁止 IP 2001:db8::7"])

    def test_apply_cleans_config_file_and_check_does_not(self):
        app.atomic_write(app.CONFIG_PATH, self.LEGACY_CONFIG)
        app.apply_once(dry_run=True)
        self.assertEqual(Path(app.CONFIG_PATH).read_text(encoding="utf-8"), self.LEGACY_CONFIG)
        self.assertIn("应用时将从配置中清除：IPv6 全部放行开关", self.output.getvalue())
        signature = app.apply_once()
        saved = Path(app.CONFIG_PATH).read_text(encoding="utf-8")
        for token in ("2001:", "allow_all_ipv6", "allow_ping"):
            self.assertNotIn(token, saved)
        self.assertEqual(signature, app.config_sig())
        self.assertEqual(app.ipv6_leftovers(), [])
        self.assertIn("已从配置中清除：IPv6 全部放行开关、直通 IP（管理地址） 2001:db8::1", self.output.getvalue())
        self.assertIn("elements = { 192.0.2.1/32, 192.0.2.8/32, 198.51.100.0/24 }", self.rules)
        self.assertNotIn("2001:", self.rules)

    def test_disabled_legacy_switch_is_dropped_silently(self):
        legacy = "rescue_ips = [\"192.0.2.1\"]\nallow_all_ipv6 = false\n"
        app.atomic_write(app.CONFIG_PATH, legacy)
        self.assertEqual(app.load_config(), config())
        self.assertEqual(app.ipv6_leftovers(), [])
        app.apply_once()
        self.assertEqual(Path(app.CONFIG_PATH).read_text(encoding="utf-8"), legacy)
        self.assertNotIn("allow_all_ipv6", app.dump_config(app.load_config()))

    def test_ipv6_only_management_address_stops_upgrade(self):
        app.atomic_write(app.CONFIG_PATH, "rescue_ips = [\"2001:db8::1\"]\n")
        with self.assertRaisesRegex(app.AppError, "管理/抢救地址只有 IPv6"):
            app.apply_once(dry_run=True)
        with self.assertRaisesRegex(app.AppError, "管理/抢救地址只有 IPv6"):
            app.initialize("")
        self.assertFalse(self.calls)

    def test_menu_rejects_ipv6_input_instead_of_dropping_it(self):
        for key in ("ips", "cidrs", "blocked_ips", "rescue_ips"):
            with self.subTest(key=key):
                self.output.seek(0)
                self.output.truncate()
                entry = "2001:db8::/48" if key == "cidrs" else "2001:db8::8"
                with patch.object(app, "read_choice", side_effect=["1", "192.0.2.50 " + entry, "0"]), \
                        patch.object(app, "ssh_source", return_value=None):
                    app.edit_list(key)
                self.assertEqual(app.load_config(), config())
                self.assertIn("操作未完成：本程序只过滤 IPv4，不支持 IPv6 地址：" + entry, self.output.getvalue())
        self.assertFalse(self.calls)

    def test_legacy_state_is_read_in_current_format(self):
        app.atomic_write(app.STATE_PATH, json.dumps({"current": self.legacy_record()}))
        self.assertEqual(app.read_state()["current"]["config"], config())
        self.assertTrue(app.legacy_rules(self.LEGACY_RULES))
        self.assertTrue(app.legacy_rules("add table inet vps_wl\ndelete table inet vps_wl\n"))
        for rules in (app.render_rules(["192.0.2.1"]), app.render_rules([], enabled=False)):
            self.assertFalse(app.legacy_rules(rules))

    def test_boot_regenerates_instead_of_restoring_legacy_inet_rules(self):
        app.atomic_write(app.STATE_PATH, json.dumps({"current": self.legacy_record()}))
        app.boot()
        self.assertEqual(self.rules, app.prepare(config()))
        self.assertNotIn(self.LEGACY_RULES, [text for text, _ in self.calls])
        self.assertEqual(app.read_state()["current"]["rules"], self.rules)
        # 之后的开机恢复原样使用新记录，不再重新生成。
        self.calls.clear()
        with patch.object(app, "prepare", side_effect=AssertionError("must restore the saved rules")):
            app.boot()
        self.assertEqual(self.calls, [(self.rules, True), (self.rules, False)])

    def test_daemon_upgrades_legacy_record_and_leftover_config(self):
        for name in ("record", "config"):
            with self.subTest(name=name):
                app.atomic_write(app.CONFIG_PATH, app.dump_config(config()))
                app.apply_once()
                if name == "record":
                    app.atomic_write(app.STATE_PATH, json.dumps({"current": self.legacy_record()}))
                else:
                    app.atomic_write(app.CONFIG_PATH, self.LEGACY_CONFIG)
                with patch.object(app, "live_table", return_value=True), \
                        patch.object(app.time, "sleep", side_effect=SystemExit), \
                        patch.object(app, "apply_once", return_value="sig") as apply:
                    with self.assertRaises(SystemExit):
                        app.daemon()
                apply.assert_called_once()

    def test_rollback_to_legacy_record_rebuilds_ipv4_rules(self):
        app.atomic_write(app.CONFIG_PATH, app.dump_config(config(ips=["192.0.2.8"])))
        app.apply_once()
        state = app.read_state()
        state["previous"] = self.legacy_record(ips=["192.0.2.9", "2001:db8::9"])
        app.atomic_write(app.STATE_PATH, json.dumps(state))
        app.rollback()
        self.assertEqual(app.load_config(), config(ips=["192.0.2.9"]))
        self.assertEqual(self.rules, app.prepare(config(ips=["192.0.2.9"])))
        self.assertFalse(app.legacy_rules(self.rules))

    def test_snapshot_covers_leftover_inet_table(self):
        listing = {"inet": "table inet vps_wl {\n}\n", "ip": "table ip vps_wl {\n}\n"}

        def run(command, input_text=None):
            if command == ["nft", "-j", "list", "tables"]:
                tables = [{"table": {"family": family, "name": "vps_wl"}} for family in present]
                tables.append({"table": {"family": "inet", "name": "other"}})
                return SimpleNamespace(returncode=0, stdout=json.dumps({"nftables": tables}), stderr="")
            self.assertEqual(command[:3] + command[4:], ["nft", "list", "table", "vps_wl"])
            return SimpleNamespace(returncode=0, stdout=listing[command[3]], stderr="")

        reset = app.render_rules([], enabled=False)
        patch.stopall()
        with patch.object(app, "run", side_effect=run):
            for present, live, snapshot in (([], False, reset), (["ip"], True, reset + listing["ip"]),
                                            (["inet"], False, reset + listing["inet"]),
                                            (["inet", "ip"], True, reset + listing["inet"] + listing["ip"])):
                with self.subTest(present=present):
                    self.assertEqual(app.live_table(), live)
                    self.assertEqual(app.live_snapshot(), snapshot)

    def test_ip_check_explains_ipv6_is_not_filtered(self):
        app.apply_once()
        with patch.object(app, "live_table", return_value=True):
            report = app.address_report("2001:db8::9")
        self.assertEqual(len(report), 1)
        self.assertIn("IPv6 不经过本程序", "\n".join(report[0][1]))

    def test_ipv6_login_is_never_warned_about_losing_access(self):
        with patch.object(app, "ssh_source", return_value="2001:db8::9"), \
                patch.object(app, "confirm", side_effect=AssertionError("must not ask")):
            self.assertTrue(app.guard_session(config()))


class Palette(Workspace):
    """白色功能文字、灰色说明，只有状态使用绿色（开启）和红色（关闭）。"""

    def render_all_pages(self):
        long_ip = "2001:db8:1234:5678:9abc:def0:1234:5678"
        cfg = config(ips=["192.0.2.8", "192.0.2.9"], cidrs=["198.51.100.0/24"], provinces=["广东", "北京"],
                     notes={"ips": {"192.0.2.8": "张三"}}, ping_mode="all",
                     paused={"ips": ["192.0.2.9"], "provinces": ["北京"]})
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        app.atomic_write(Path(app.CACHE_DIR) / "440000.txt", "198.51.100.0/24\n")
        with patch.object(app, "interactive_terminal", return_value=True), \
                patch.dict(os.environ, {"NO_COLOR": ""}), \
                patch.object(app, "read_choice", return_value="0"):
            for enabled, active in ((True, True), (False, False), (True, False)):
                app.render_home(config(enabled=enabled, ping_mode="all" if enabled else "off"), active, long_ip,
                                active, "已保存并生效。")
            app.whitelist_menu()
            for key in app.LIST_KEYS:
                app.edit_list(key)
            app.province_input(cfg["provinces"], cfg["paused"]["provinces"])
            app.options_menu()
            app.atomic_write(app.CONFIG_PATH, app.dump_config(dict(cfg, protect_dnat=False)))
            app.options_menu()
            app.ping_menu()
            app.maintenance_menu()
            app.view_local_province_packages()
            app.program_page()
            app.list_page("完整列表", cfg["ips"], 0, notes=cfg["notes"]["ips"], paused=cfg["paused"]["ips"])
            app.confirm("确认？")
            app.notice("已取消添加。")
            app.notice("操作未完成：测试")
        return self.output.getvalue().replace("\033[2J\033[H", "")

    def test_only_white_gray_green_and_red_are_used(self):
        codes = set(re.findall(r"\033\[([0-9;]*)m", self.render_all_pages()))
        self.assertTrue(codes)
        self.assertLessEqual(codes, {"0", "1", "2", "31", "32", "1;31", "1;32"})

    def test_same_state_words_always_share_one_color(self):
        output = self.render_all_pages()
        colored = re.findall(r"\033\[([0-9;]*)m([^\033]*)\033\[0m", output)
        seen = {}
        for code, text in colored:
            for word in ("已开启", "已关闭", "已暂停", "启用", "暂停", "防护中"):
                if word in text:
                    seen.setdefault(word, set()).add(code.split(";")[-1])
        on_words, off_words = ("已开启", "启用", "防护中"), ("已关闭", "已暂停", "暂停")
        # 白色标题、灰色说明里可以出现这些词；一旦着色（绿 / 红），必须与状态一致。
        for word, found in seen.items():
            self.assertEqual(found - {"1", "2"}, {"32"} if word in on_words else {"31"}, word)
        self.assertTrue({"已开启", "已关闭", "启用", "暂停"} <= set(seen))


class Layout(Workspace):
    def test_every_page_keeps_box_borders_aligned(self):
        long_ip = "2001:db8:1234:5678:9abc:def0:1234:5678"
        cfg = config(ips=["192.0.2.%d" % x for x in range(1, 9)] + ["198.51.100.200"],
                     cidrs=["203.0.113.128/25"], provinces=["广东", "内蒙古"], blocked_ips=["198.51.100.7"],
                     notes={"ips": {"198.51.100.200": "办公室宽带，备注较长时需要自动折行而不破坏右侧边框"}},
                     paused={"ips": ["192.0.2.2"], "provinces": ["内蒙古"]})
        app.atomic_write(app.CONFIG_PATH, app.dump_config(cfg))
        app.atomic_write(Path(app.CACHE_DIR) / "440000.txt", "198.51.100.0/24\n")
        for columns in (40, 50, 64, 80, 200):
            with self.subTest(columns=columns), \
                    patch.object(app.shutil, "get_terminal_size", return_value=os.terminal_size((columns, 24))), \
                    patch.object(app, "read_choice", return_value="0"):
                self.output.seek(0)
                self.output.truncate()
                for active in (True, False):
                    app.render_home(cfg, active, long_ip, False, "已保存并生效。")
                app.whitelist_menu()
                for key in app.LIST_KEYS:
                    app.edit_list(key)
                app.province_input(cfg["provinces"], cfg["paused"]["provinces"])
                app.options_menu()
                app.ping_menu()
                app.maintenance_menu()
                app.view_local_province_packages()
                app.program_page()
                app.list_page("白名单 / IP 白名单 / 完整列表", cfg["ips"], 0, "提示",
                              notes=cfg["notes"]["ips"], paused=cfg["paused"]["ips"])
                app.confirm("当前登录 IP %s 将失去权限，SSH 可能立即断开。继续？" % long_ip)
                width = app.ui_width() + 2
                boxed = [line for line in self.output.getvalue().splitlines()
                         if line[2:3] in tuple("╔║╚╭│├╰")]
                self.assertTrue(boxed)
                for line in boxed:
                    self.assertEqual(app.display_width(line), width, line)


if __name__ == "__main__":
    unittest.main()
