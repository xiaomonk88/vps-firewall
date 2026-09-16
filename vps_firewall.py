#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Debian 12/13 vps-firewall。只管理 inet vps_wl 表，不改系统 nftables.conf。"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import unicodedata
from contextlib import contextmanager

try:
    import tomllib
except ImportError:
    tomllib = None

try:
    APP_VERSION = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip() or "未知"
except OSError:
    APP_VERSION = "未知"

# Release date, kept with the code so older GitHub installers also carry it forward.
APP_RELEASE_DATE = "2026.09.16"

CONFIG_PATH = "/etc/vps-firewall/config.toml"
DATA_DIR = "/var/lib/vps-firewall"
CACHE_DIR = DATA_DIR + "/province_cache"
STATE_PATH = DATA_DIR + "/state.json"
SYSTEM_RULES_PATH = "/etc/nftables.conf"
LOCK_PATH = "/run/lock/vps-firewall.lock"
TABLE = "vps_wl"
DEFAULT_PROVINCE_BASES = [
    "https://raw.githubusercontent.com/metowolf/iplist/master/data/cncity",
    "https://raw.gitmirror.com/metowolf/iplist/master/data/cncity",
    "https://ghproxy.net/https://raw.githubusercontent.com/metowolf/iplist/master/data/cncity",
]
PROVINCE_CODES = {
    "北京": "110000", "北京市": "110000", "京": "110000",
    "天津": "120000", "天津市": "120000", "津": "120000",
    "河北": "130000", "河北省": "130000", "冀": "130000",
    "山西": "140000", "山西省": "140000", "晋": "140000",
    "内蒙古": "150000", "内蒙古自治区": "150000", "内蒙": "150000",
    "辽宁": "210000", "辽宁省": "210000", "辽": "210000",
    "吉林": "220000", "吉林省": "220000", "吉": "220000",
    "黑龙江": "230000", "黑龙江省": "230000", "黑": "230000",
    "上海": "310000", "上海市": "310000", "沪": "310000",
    "江苏": "320000", "江苏省": "320000", "苏": "320000",
    "浙江": "330000", "浙江省": "330000", "浙": "330000",
    "安徽": "340000", "安徽省": "340000", "皖": "340000",
    "福建": "350000", "福建省": "350000", "闽": "350000",
    "江西": "360000", "江西省": "360000", "赣": "360000",
    "山东": "370000", "山东省": "370000", "鲁": "370000",
    "河南": "410000", "河南省": "410000", "豫": "410000",
    "湖北": "420000", "湖北省": "420000", "鄂": "420000",
    "湖南": "430000", "湖南省": "430000", "湘": "430000",
    "广东": "440000", "广东省": "440000", "粤": "440000",
    "广西": "450000", "广西壮族自治区": "450000", "桂": "450000",
    "海南": "460000", "海南省": "460000", "琼": "460000",
    "重庆": "500000", "重庆市": "500000", "渝": "500000",
    "四川": "510000", "四川省": "510000", "川": "510000",
    "贵州": "520000", "贵州省": "520000", "黔": "520000",
    "云南": "530000", "云南省": "530000", "滇": "530000",
    "西藏": "540000", "西藏自治区": "540000", "藏": "540000",
    "陕西": "610000", "陕西省": "610000", "陕": "610000",
    "甘肃": "620000", "甘肃省": "620000", "甘": "620000",
    "青海": "630000", "青海省": "630000", "青": "630000",
    "宁夏": "640000", "宁夏回族自治区": "640000", "宁": "640000",
    "新疆": "650000", "新疆维吾尔自治区": "650000", "新": "650000",
    "台湾": "710000", "台湾省": "710000",
    "香港": "810000", "香港特别行政区": "810000",
    "澳门": "820000", "澳门特别行政区": "820000",
}

PROVINCE_NAMES = list(dict.fromkeys(
    next(name for name, value in PROVINCE_CODES.items() if value == code)
    for code in dict.fromkeys(PROVINCE_CODES.values())
))
DEFAULTS = dict(enabled=True, rescue_ips=[], provinces=[], cidrs=[], ips=[],
                blocked_ips=[], allow_ping=True, allow_all_ipv6=False,
                protect_dnat=True,
                watch_interval=5, province_refresh=86400, province_source_base="")
LABELS = dict(rescue_ips="管理/抢救地址", provinces="省份白名单",
              cidrs="网段白名单", ips="单 IP 白名单", blocked_ips="禁止访问")
LIST_KEYS = tuple(LABELS)


class AppError(Exception):
    pass


def log(message):
    print("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message), flush=True)


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if sys.platform == "linux":
            directory_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def operation_lock():
    # Linux only; importing the module and running pure logic tests works on Windows.
    import fcntl
    Path(LOCK_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_PATH, "a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def norm(value):
    value = str(value).strip()
    if "%" in value:
        raise AppError("地址不能包含接口区域标记：%s" % value)
    try:
        obj = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
        return str(obj)
    except ValueError as exc:
        raise AppError("无效 IP 或网段：%s" % value) from exc


def resolve_province_code(name):
    return PROVINCE_CODES.get(str(name).strip())


def validate_config(raw):
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise AppError("不支持的配置项：%s" % ", ".join(sorted(unknown)))
    cfg = copy.deepcopy(DEFAULTS)
    cfg.update(raw)
    for key in ("enabled", "allow_ping", "allow_all_ipv6", "protect_dnat"):
        if type(cfg[key]) is not bool:
            raise AppError("%s 必须为 true 或 false" % key)
    for key, minimum in (("watch_interval", 5), ("province_refresh", 0)):
        if type(cfg[key]) is not int or cfg[key] < minimum:
            raise AppError("%s 必须是至少 %d 的整数" % (key, minimum))
    if not isinstance(cfg["province_source_base"], str):
        raise AppError("province_source_base 必须是字符串")
    src = cfg["province_source_base"].strip()
    if src and not src.startswith(("https://", "http://")):
        raise AppError("省份数据源必须是 http/https 地址")
    cfg["province_source_base"] = src
    for key in LIST_KEYS:
        if not isinstance(cfg[key], list) or not all(isinstance(x, str) for x in cfg[key]):
            raise AppError("%s 必须是字符串数组" % key)
        entries = []
        for item in cfg[key]:
            if key == "provinces":
                code = resolve_province_code(item)
                if not code:
                    raise AppError("未知省份：%s" % item)
                value = next(n for n in PROVINCE_NAMES if PROVINCE_CODES[n] == code)
            else:
                value = norm(item)
                if key in ("ips", "blocked_ips") and "/" in value:
                    raise AppError("%s 只接受单 IP；网段请放到网段白名单" % LABELS[key])
            if value not in entries:
                entries.append(value)
        cfg[key] = entries
    if cfg["enabled"] and not cfg["rescue_ips"]:
        raise AppError("开启过滤至少保留一个管理/抢救地址，请先添加备用管理地址")
    blocked = [ipaddress.ip_address(x) for x in cfg["blocked_ips"]]
    for entry in cfg["rescue_ips"]:
        network = ipaddress.ip_network(entry, strict=False)
        if any(ip in network for ip in blocked):
            raise AppError("禁止地址与管理/抢救地址 %s 重叠；请先调整管理地址" % entry)
    return cfg


def load_config(path=None):
    if tomllib is None:
        raise AppError("需要 Python 3.11 或更高版本")
    with open(path or CONFIG_PATH, "rb") as stream:
        return validate_config(tomllib.load(stream))


def dump_config(cfg):
    cfg = validate_config(cfg)
    lines = ["# vps-firewall配置；手动修改后自动重载。菜单保存会重新整理格式。",
             "# 白名单取并集；禁止访问优先；管理地址不得与禁止地址重叠。"]
    for key in DEFAULTS:
        value = cfg[key]
        if key in LABELS:
            lines.append("\n# " + LABELS[key])
        # JSON strings, lists and booleans are valid for this TOML schema.
        lines.append(key + " = " + json.dumps(value, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def config_sig():
    return hashlib.sha256(Path(CONFIG_PATH).read_bytes()).hexdigest()


def parse_province(data):
    networks = set()
    for line in data.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        value = norm(line)
        if ipaddress.ip_network(value, strict=False).version != 4:
            raise AppError("省份数据包含非 IPv4 地址")
        networks.add(value)
    if not networks:
        raise AppError("省份数据为空")
    return networks


def fetch_provinces(provinces, refresh_seconds, base_urls, force=False, write_cache=True):
    result = set()
    for name in provinces:
        code = resolve_province_code(name)
        if not code:
            raise AppError("未知省份：%s" % name)
        path = Path(CACHE_DIR) / (code + ".txt")
        cached = None
        if path.exists():
            try:
                cached = parse_province(path.read_text(encoding="utf-8"))
            except (OSError, AppError, UnicodeError) as exc:
                log("缓存无效 %s：%s" % (name, exc))
        stale = not cached or (refresh_seconds > 0 and time.time() - path.stat().st_mtime >= refresh_seconds)
        if force or stale:
            downloaded = None
            for base in base_urls:
                url = "%s/%s.txt" % (base.rstrip("/"), code)
                try:
                    request = urllib.request.Request(url, headers={"User-Agent": "vps-firewall/2.0"})
                    with urllib.request.urlopen(request, timeout=12) as response:
                        data = response.read(8 * 1024 * 1024 + 1)
                    if len(data) > 8 * 1024 * 1024:
                        raise AppError("数据文件过大")
                    downloaded = parse_province(data.decode("utf-8-sig"))
                    break
                except Exception as exc:
                    log("省份 %s 下载失败：%s" % (name, exc))
            if downloaded:
                cached = downloaded
                if write_cache:
                    atomic_write(path, "\n".join(sorted(cached)) + "\n")
                log("已获取省份 %s：%d 个网段" % (name, len(cached)))
            elif cached:
                log("省份 %s 使用旧缓存；保留原缓存时间，下次重试" % name)
            else:
                raise AppError("省份 %s 无可用数据；本次变更未应用，保留现有规则" % name)
        result.update(cached)
    return result


def build_allowlist(cfg, force_refresh=False, write_cache=True):
    allow = set(cfg["rescue_ips"] + cfg["cidrs"] + cfg["ips"])
    if cfg["provinces"]:
        bases = ([cfg["province_source_base"]] if cfg["province_source_base"] else []) + DEFAULT_PROVINCE_BASES
        allow.update(fetch_provinces(cfg["provinces"], cfg["province_refresh"], bases,
                                    force=force_refresh, write_cache=write_cache))
    # No runtime SSH discovery: a removed address must never silently return.
    return allow


def collapse(entries, version):
    nets = [ipaddress.ip_network(x, strict=False) for x in entries]
    return [str(n) for n in ipaddress.collapse_addresses(n for n in nets if n.version == version)]


def render_rules(allowlist, allow_ping=True, allow_all_ipv6=False, blocked_ips=(), enabled=True,
                 protect_dnat=True):
    # One atomic nft transaction. "add table" succeeds even when the table exists.
    lines = ["add table inet " + TABLE, "delete table inet " + TABLE]
    if not enabled:
        return "\n".join(lines) + "\n"
    lines.append("table inet " + TABLE + " {")
    for prefix, entries in (("allow", allowlist), ("blocked", blocked_ips)):
        for version in (4, 6):
            values = collapse(entries, version)
            lines += ["    set %s%d {" % (prefix, version),
                      "        type ipv%d_addr" % version, "        flags interval"]
            if values:
                lines.append("        elements = { " + ", ".join(values) + " }")
            lines.append("    }")
    lines += ["    chain input {",
              "        type filter hook input priority 10; policy drop;",
              '        iifname "lo" accept',
              "        ct state invalid drop",
              "        ip saddr @blocked4 counter drop",
              "        ip6 saddr @blocked6 counter drop",
              # Only replies to connections originated by this VPS bypass source membership.
              "        ct direction reply ct state established,related accept",
              # IPv6 link control is needed even when inbound services are restricted.
              "        meta l4proto ipv6-icmp ip6 hoplimit 255 icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept",
              "        ct state related meta l4proto { icmp, ipv6-icmp } accept"]
    if allow_ping:
        lines += ["        icmp type echo-request accept", "        icmpv6 type echo-request accept"]
    if allow_all_ipv6:
        lines.append("        meta nfproto ipv6 accept")
    lines += ["        ip saddr @allow4 accept", "        ip6 saddr @allow6 accept",
              "        counter drop", "    }"]
    if protect_dnat:
        # Published Docker/NAT ports traverse forward instead of input.
        # Scope to DNAT original direction; ordinary routing and container egress stay untouched.
        lines += ["    chain published {", "        ip saddr @blocked4 counter drop",
                  "        ip6 saddr @blocked6 counter drop"]
        if allow_all_ipv6:
            lines.append("        meta nfproto ipv6 accept")
        lines += ["        ip saddr @allow4 accept", "        ip6 saddr @allow6 accept",
                  "        counter drop", "    }", "    chain forward {",
                  "        type filter hook forward priority 10; policy accept;",
                  "        ct status dnat ct direction original jump published", "    }"]
    lines.append("}")
    return "\n".join(lines) + "\n"


def run(command, input_text=None):
    try:
        return subprocess.run(command, input=input_text, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AppError("命令执行失败 %s：%s" % (command[0], exc)) from exc


def nft(text, check=False):
    result = run(["nft"] + (["-c"] if check else []) + ["-f", "-"], text)
    if result.returncode:
        raise AppError("防火墙%s失败：%s" % ("校验" if check else "应用", result.stderr.strip()))


def live_table():
    result = run(["nft", "-j", "list", "tables"])
    if result.returncode:
        raise AppError("无法读取防火墙：" + result.stderr.strip())
    tables = json.loads(result.stdout).get("nftables", [])
    return any(x.get("table", {}).get("family") == "inet" and
               x.get("table", {}).get("name") == TABLE for x in tables)


def live_snapshot():
    if not live_table():
        return render_rules([], enabled=False)
    result = run(["nft", "list", "table", "inet", TABLE])
    if result.returncode:
        raise AppError("无法备份当前白名单规则：" + result.stderr.strip())
    return "add table inet %s\ndelete table inet %s\n%s" % (TABLE, TABLE, result.stdout)


def read_state():
    if not Path(STATE_PATH).exists():
        return {}
    try:
        return json.loads(Path(STATE_PATH).read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise AppError("运行状态文件无法读取：" + str(exc)) from exc


def prepare(cfg, force=False, dry_run=False):
    cfg = validate_config(cfg)
    allow = build_allowlist(cfg, force, write_cache=not dry_run) if cfg["enabled"] else set()
    return render_rules(allow, cfg["allow_ping"], cfg["allow_all_ipv6"],
                        cfg["blocked_ips"], cfg["enabled"], cfg["protect_dnat"])


def journal_path():
    return Path(STATE_PATH).with_name("pending.json")


def recover_pending():
    """A process/disk failure cannot leave an uncommitted policy as the boot policy."""
    path = journal_path()
    if not path.exists():
        return
    pending = json.loads(path.read_text(encoding="utf-8"))
    if read_state() == pending["after"]:
        # Commit marker persisted: complete the config write, do not undo a successful change.
        if pending["save"]:
            atomic_write(CONFIG_PATH, dump_config(pending["after"]["current"]["config"]))
    else:
        nft(pending["rules_before"])
        if pending["save"]:
            atomic_write(CONFIG_PATH, pending["config_before"])
    path.unlink()
    log("已恢复中断的应用事务")


def commit(cfg, rules, save=False, state=None):
    """Caller holds lock. Verify first; restore previous live table on persistence failure."""
    state = read_state() if state is None else state
    previous_rules = live_snapshot()
    old_config = Path(CONFIG_PATH).read_text(encoding="utf-8")
    nft(rules, check=True)
    current = {"config": cfg, "rules": rules, "applied_at": time.time()}
    new_state = {"current": current, "previous": state.get("previous")}
    old_current = state.get("current")
    if old_current and (old_current["config"] != cfg or old_current["rules"] != rules):
        new_state["previous"] = old_current
    pending = dict(after=new_state, rules_before=previous_rules, config_before=old_config, save=save)
    atomic_write(journal_path(), json.dumps(pending, ensure_ascii=False))
    try:
        nft(rules)
        if save:
            atomic_write(CONFIG_PATH, dump_config(cfg))
        atomic_write(STATE_PATH, json.dumps(new_state, ensure_ascii=False, indent=2))
    except Exception as exc:
        try:
            recover_pending()
        except Exception as rollback_error:
            raise AppError("应用失败且恢复未完成：%s；%s。保留恢复记录，请从控制台重试" %
                           (exc, rollback_error)) from exc
        raise AppError("应用或保存发生错误，已执行事务恢复；请查看状态：%s" % exc) from exc
    journal_path().unlink()
    log("已生效：%s" % ("白名单过滤开启" if cfg["enabled"] else "本程序过滤已关闭"))


def apply_once(dry_run=False, force_refresh=False):
    with operation_lock():
        if not dry_run:
            recover_pending()
        signature = config_sig()
        cfg = load_config()
        rules = prepare(cfg, force_refresh, dry_run)
        if config_sig() != signature:
            raise AppError("处理期间配置文件发生变化，请重试")
        if dry_run:
            nft(rules, check=True)
            log("配置和规则校验通过；未修改防火墙、配置或缓存")
        else:
            commit(cfg, rules)
        return signature


def edit_config(original, candidate):
    candidate = validate_config(candidate)
    with operation_lock():
        recover_pending()
        if load_config() != original:
            raise AppError("配置已被其他操作修改，请返回并重新操作")
        rules = prepare(candidate, force=original["province_source_base"] != candidate["province_source_base"])
        if load_config() != original:
            raise AppError("下载期间配置已被修改，请重新操作")
        commit(candidate, rules, save=True)


def rollback():
    with operation_lock():
        recover_pending()
        state = read_state()
        previous = state.get("previous")
        if not previous:
            raise AppError("暂无上一版成功配置；至少成功修改一次后才可回滚")
        cfg = validate_config(previous["config"])
        # Restore exact prior own-table rules, including prior province contents.
        commit(cfg, previous["rules"], save=True, state=state)
    log("已恢复上一版配置及本程序规则；其他防火墙规则不受影响")


def boot():
    # No network fetch needed to restore a successfully applied policy after reboot.
    with operation_lock():
        recover_pending()
        current = read_state().get("current")
        if current:
            nft(current["rules"], check=True)
            nft(current["rules"])
            log("已恢复上次成功规则；守护进程随后检查配置变化")
            return
    apply_once()


def daemon():
    log("守护进程启动")
    last_sig = None
    last_refresh = time.monotonic()
    retry_at = 0.0
    while True:
        watch = 5
        try:
            cfg = load_config()
            watch = cfg["watch_interval"]
            sig = config_sig()
            recorded = read_state().get("current")
            unsynced = not recorded or recorded["config"] != cfg
            refresh = cfg["province_refresh"]
            due = cfg["enabled"] and refresh > 0 and time.monotonic() - last_refresh >= refresh
            missing = live_table() != cfg["enabled"]
            if (sig != last_sig or due or missing or unsynced) and time.monotonic() >= retry_at:
                with operation_lock():
                    recover_pending()
                    current = read_state().get("current")
                if not due and not missing and current and current["config"] == cfg:
                    # Menu/rollback already committed the exact rules. Do not overwrite its snapshot.
                    last_sig = sig
                else:
                    last_sig = apply_once(force_refresh=due)
                last_refresh = time.monotonic()
                retry_at = 0
        except Exception as exc:
            log("未应用：%s；稍后重试" % exc)
            retry_at = time.monotonic() + 15
        time.sleep(watch)


def ssh_source():
    # SSH_CONNECTION includes custom SSH ports and IPv6 without port-specific probing.
    candidates = [os.environ.get("SSH_CONNECTION", "")]
    # sudo often filters the variable. Inspect only our ancestor chain, never all sessions.
    if not candidates[0] and sys.platform == "linux":
        pid = os.getppid()
        for _ in range(8):
            try:
                environment = Path("/proc/%d/environ" % pid).read_bytes().split(b"\0")
                candidates.extend(value.split(b"=", 1)[1].decode("ascii", "ignore")
                                  for value in environment if value.startswith(b"SSH_CONNECTION="))
                status_text = Path("/proc/%d/status" % pid).read_text()
                parent = re.search(r"^PPid:\s+(\d+)", status_text, re.M)
                pid = int(parent.group(1)) if parent else 0
                if pid <= 1 or len(candidates) > 1:
                    break
            except OSError:
                break
    for candidate in candidates:
        value = candidate.split()
        if not value:
            continue
        try:
            return str(ipaddress.ip_address(value[0]))
        except ValueError:
            pass
    return None


def matching_sources(cfg, address, use_cache=True):
    ip = ipaddress.ip_address(address)
    reasons = []
    for key in ("rescue_ips", "ips", "cidrs"):
        for item in cfg[key]:
            if ip in ipaddress.ip_network(item, strict=False):
                reasons.append("%s：%s" % (LABELS[key], item))
    if ip.version == 6 and cfg["allow_all_ipv6"]:
        reasons.append("全部 IPv6 放行开关")
    if ip.version == 4 and use_cache:
        for name in cfg["provinces"]:
            path = Path(CACHE_DIR) / (resolve_province_code(name) + ".txt")
            if not path.exists():
                log("省份 %s 缓存缺失，无法确认其是否覆盖该 IP" % name)
                continue
            networks = parse_province(path.read_text(encoding="utf-8"))
            if any(ip in ipaddress.ip_network(n, strict=False) for n in networks):
                reasons.append("省份白名单：" + name)
    return reasons


def status():
    print("  程序版本：vps-firewall " + APP_VERSION)
    with operation_lock():
        cfg = load_config()
        state = read_state()
        active = live_table()
        service = run(["systemctl", "is-active", "vps-firewall"]).stdout.strip()
        current = state.get("current")
        print("  防护状态：" + protection_status(cfg, active))
        print("  后台服务：" + {"active": "运行中", "inactive": "未运行", "failed": "启动失败"}.get(service, service))
        print("  配置同步：" + ("已同步" if current and current["config"] == cfg else "等待应用，请检查日志"))
        print("  公网 ping：" + ("允许" if cfg["allow_ping"] else "仅白名单"))
        print("  IPv6 访问：" + ("全部放行" if cfg["allow_all_ipv6"] else "按白名单放行"))
        print("  映射端口保护：" + ("开启" if cfg["protect_dnat"] else "关闭"))
        if current:
            print("  最近生效：" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current["applied_at"])))
        for key in LIST_KEYS:
            print("\n  %s · %d 项" % (LIST_TITLES[key], len(cfg[key])))
            for item in cfg[key]:
                print("    " + item)
            if not cfg[key]:
                print("    暂无")
        return cfg


# Terminal UI: one action per line, stable navigation, no third-party dependencies.
PAGE_SIZE = 12
LIST_TITLES = {
    "ips": "IP白名单",
    "cidrs": "网段白名单",
    "provinces": "省份白名单",
    "blocked_ips": "禁止 IP",
    "rescue_ips": "直通IP地址",
}
LIST_HINTS = {
    "ips": "支持 IPv4 / IPv6；多个地址用空格或逗号分隔。",
    "cidrs": "输入网段，如 203.0.113.0/24；支持 IPv4 / IPv6。",
    "provinces": "选择省份后，放行该省份的 IPv4 地址。",
    "blocked_ips": "禁止优先于普通白名单；不能与直通IP地址重叠。",
    "rescue_ips": "用于登录管理服务器；开启防护时至少保留一个。",
}


def read_choice(prompt):
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return "0"


def confirm(message):
    print("\n  " + message)
    menu_table([(1, "确认", ""), (0, "取消", "默认")])
    return read_choice("选择 [默认取消]：").lower() in ("1", "y")


def heading(title):
    # Clear only an interactive screen, preserving scrollback and readable redirected output.
    if sys.stdout.isatty() and os.environ.get("TERM") != "dumb":
        print("\033[2J\033[H", end="")
    print()
    rows = [("vps-firewall " + APP_VERSION + "        " + APP_RELEASE_DATE,)]
    if title:
        rows.append((title,))
    table(rows)


def display_width(text):
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
               for char in str(text))


def wrap_cell(text, width):
    lines = []
    for paragraph in str(text).split("\n"):
        line = ""
        used = 0
        for char in paragraph:
            size = display_width(char)
            if used + size > width:
                lines.append(line)
                line, used = "", 0
            line += char
            used += size
        lines.append(line)
    return lines


def table(rows, headers=None, sections=None):
    """Render CJK-aware borders; wrap long addresses instead of cutting them off."""
    rows = [tuple(str(cell) for cell in row) for row in rows]
    columns = len(headers) if headers else len(rows[0])
    total = max(30, min(60, shutil.get_terminal_size((80, 24)).columns - 4))
    widths = [total - 4] if columns == 1 else [4, total - 26, 12]

    def border(left, middle, right):
        print("  " + left + middle.join("─" * (width + 2) for width in widths) + right)

    def row(cells, cell_widths=None):
        cell_widths = widths if cell_widths is None else cell_widths
        wrapped = [wrap_cell(cell, width) for cell, width in zip(cells, cell_widths)]
        for index in range(max(map(len, wrapped))):
            values = [lines[index] if index < len(lines) else "" for lines in wrapped]
            print("  │" + "│".join(" " + value + " " * (width - display_width(value) + 1)
                                    for value, width in zip(values, cell_widths)) + "│")

    border("┌", "┬", "┐")
    if headers:
        row(headers)
        if not sections or 0 not in sections:
            border("├", "┼", "┤")
    for index, cells in enumerate(rows):
        if sections and index in sections:
            title = sections[index]
            if title:
                border("├", "┴", "┤")
                row((title,), [sum(widths) + 3 * (len(widths) - 1)])
                border("├", "┬", "┤")
            else:
                border("├", "┼", "┤")
        row(cells)
    border("└", "┴", "┘")


def menu_table(rows, sections=None):
    table(rows, headers=("编号", "功能", "数量 / 状态"), sections=sections)


def notice(message):
    if message:
        print("\n  " + message)


def pause():
    read_choice("\n按回车返回，0 也可返回：")


def protection_status(cfg, active):
    if cfg["enabled"] and active:
        return "已开启"
    if not cfg["enabled"] and not active:
        return "已暂停"
    return "待同步，请查看运行状态"


def render_home(cfg, active, source=None, synced=True, message=""):
    heading("")
    print()
    count = sum(len(cfg[key]) for key in ("ips", "cidrs", "provinces"))
    menu_table([
        (1, "白名单管理", "%d 项" % count),
        (2, "禁止IP", "%d 项" % len(cfg["blocked_ips"])),
        (3, "直通IP地址", "%d 项" % len(cfg["rescue_ips"])),
        (4, "IP访问权限", ""),
        (5, "访问设置", ""),
        (6, "维护与日志", ""),
        (7, "暂停防护" if cfg["enabled"] else "开启防护", ""),
        (8, "更新程序", ""),
        (9, "卸载程序", ""),
        (0, "退出", ""),
    ], sections={0: "一、IP管理", 4: "二、系统控制", 7: "三、版本控制", 9: ""})
    notice(message)
    if not synced or cfg["enabled"] != active:
        print("\n  提醒：配置尚未同步，请到“维护与日志”检查。")
    state = "开启" if active else "关闭"
    if sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ:
        state = "\033[%sm%s\033[0m" % ("32" if active else "31", state)
    print("\n  防火墙：%s  当前IP：%s" % (state, source or "未检测到"))


def whitelist_menu():
    message = ""
    while True:
        cfg = load_config()
        heading("白名单管理")
        keys = {"1": "ips", "2": "cidrs", "3": "provinces"}
        menu_table([(number, LIST_TITLES[key], "%d 项" % len(cfg[key]))
                    for number, key in keys.items()] + [(0, "返回主菜单", "")])
        notice(message)
        choice = read_choice("请选择：")
        message = ""
        if choice == "0":
            return
        if choice in keys:
            edit_list(keys[choice])
        elif choice:
            message = "请输入 0 到 3 之间的编号。"


def guard_session(candidate):
    source = ssh_source()
    if not source or not candidate["enabled"]:
        return True
    covered = source not in candidate["blocked_ips"] and bool(matching_sources(candidate, source))
    if not covered:
        return confirm("当前登录 IP %s 将失去权限，SSH 可能立即断开。继续？" % source)
    return True


def save_from_menu(original, candidate):
    candidate = validate_config(candidate)
    if candidate == original:
        return "没有变更，无需保存。"
    if not guard_session(candidate):
        return "已取消，配置未修改。"
    print("\n  正在保存并应用，请稍候…", flush=True)
    edit_config(original, candidate)
    return "已保存并生效。" if candidate["enabled"] else "已保存。防护目前暂停，开启后生效。"


def split_values(text):
    return [x for x in re.split(r"[,，、;；\s]+", text.strip()) if x]


def list_page(title, items, page=0, selected=()):
    heading(title)
    pages = max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)
    print("  共 %d 项 · 第 %d / %d 页\n" % (len(items), page + 1, pages))
    rows = [(index + 1, items[index], "已添加" if items[index] in selected else "")
            for index in range(page * PAGE_SIZE, min((page + 1) * PAGE_SIZE, len(items)))]
    table(rows or [("—", "暂无条目", "")], headers=("编号", "条目", "状态"))
    print()
    if page + 1 < pages:
        print("  n. 下一页")
    if page:
        print("  p. 上一页")
    print("  0. 返回")
    return pages


def next_page(value, page, pages):
    if value.lower() == "n":
        return min(page + 1, pages - 1)
    if value.lower() == "p":
        return max(page - 1, 0)
    return None


def province_input(selected=()):
    page = 0
    message = ""
    while True:
        pages = list_page("省份白名单 / 添加", PROVINCE_NAMES, page, selected)
        print("\n  输入编号或名称；支持多个，例如：1 2 或 北京,广东。")
        notice(message)
        value = read_choice("添加省份 [0 取消]：")
        target = next_page(value, page, pages)
        if target is not None:
            page = target
            message = ""
            continue
        if value in ("0", ""):
            return "0"
        values = split_values(value)
        names = [PROVINCE_NAMES[int(x) - 1] if x.isdigit() and 1 <= int(x) <= len(PROVINCE_NAMES) else x for x in values]
        if not all(resolve_province_code(x) for x in names):
            message = "未识别省份，请输入有效编号或名称。"
            continue
        return " ".join(names)


def view_list(key):
    page = 0
    while True:
        items = load_config()[key]
        page = min(page, max(0, (len(items) - 1) // PAGE_SIZE))
        pages = list_page(LIST_TITLES[key] + " / 完整列表", items, page)
        value = read_choice("选择 [0 返回]：")
        if value in ("0", ""):
            return
        target = next_page(value, page, pages)
        if target is not None:
            page = target


def select_entries(key, items):
    page = 0
    message = ""
    while True:
        pages = list_page(LIST_TITLES[key] + " / 选择要移除的条目", items, page)
        print("\n  可输入多个编号或范围，例如：1 3 或 2-5。")
        notice(message)
        value = read_choice("移除编号 [0 取消]：")
        target = next_page(value, page, pages)
        if target is not None:
            page = target
            message = ""
            continue
        if value in ("0", ""):
            return set()
        indices = set()
        try:
            for token in split_values(value):
                match = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
                if not match:
                    raise ValueError
                first = int(match.group(1))
                last = int(match.group(2) or first)
                if not 1 <= first <= last <= len(items):
                    raise ValueError
                indices.update(range(first - 1, last))
            if not indices:
                raise ValueError
            return {items[index] for index in indices}
        except ValueError:
            message = "编号无效，请按列表编号重新选择。"


def revoke_addresses(cfg, addresses):
    """Explicitly revoke single hosts, including duplicate single-host rescue entries."""
    candidate = copy.deepcopy(cfg)
    targets = {ipaddress.ip_address(x) for x in addresses}
    candidate["ips"] = [x for x in cfg["ips"] if ipaddress.ip_address(x) not in targets]
    retained = []
    for entry in cfg["rescue_ips"]:
        network = ipaddress.ip_network(entry, strict=False)
        if any(ip in network for ip in targets):
            if network.prefixlen != network.max_prefixlen:
                raise AppError("该 IP 位于管理网段 %s 内，请先缩小/调整管理网段后再禁止" % entry)
        else:
            retained.append(entry)
    candidate["rescue_ips"] = retained
    candidate["blocked_ips"] = sorted(set(candidate["blocked_ips"]) | {str(x) for x in targets})
    return validate_config(candidate)


def edit_list(key):
    message = ""
    while True:
        cfg = load_config()
        items = cfg[key]
        heading(LIST_TITLES[key])
        print("  " + LIST_HINTS[key])
        print("\n  当前列表 · %d 项" % len(items))
        for item in items[:5]:
            print("    · " + item)
        if len(items) > 5:
            print("    … 还有 %d 项，可选择“查看完整列表”。" % (len(items) - 5))
        if not items:
            print("    暂无，选择“添加”开始设置。")
        print()
        menu_table([(1, "添加", ""),
                    (2, "解除禁止" if key == "blocked_ips" else "移除", ""),
                    (3, "查看完整列表", ""),
                    (0, "返回白名单管理" if key in ("ips", "cidrs", "provinces") else "返回主菜单", "")])
        notice(message)
        choice = read_choice("请选择：")
        message = ""
        if choice == "0":
            return
        if choice == "":
            continue
        candidate = copy.deepcopy(cfg)
        try:
            if choice == "1":
                if key == "provinces":
                    raw = province_input(items)
                else:
                    heading(LIST_TITLES[key] + " / 添加")
                    print("  " + LIST_HINTS[key])
                    print("  多项可用空格或逗号分隔；0 取消。\n")
                    raw = read_choice("请输入网段：" if key == "cidrs" else "请输入 IP 或地址：")
                if raw in ("0", ""):
                    message = "已取消添加。"
                    continue
                values = split_values(raw)
                candidate[key].extend(values)
                if key == "ips":
                    addresses = [norm(x) for x in values]
                    blocked = set(addresses) & set(cfg["blocked_ips"])
                    if blocked:
                        if not confirm("以下 IP 当前被禁止，将同时解除禁止：" + "、".join(sorted(blocked))):
                            message = "已取消添加。"
                            continue
                        candidate["blocked_ips"] = [x for x in cfg["blocked_ips"] if x not in blocked]
            elif choice == "2":
                if not items:
                    message = "列表为空，没有可移除的条目。"
                    continue
                selected = select_entries(key, items)
                if not selected:
                    message = "已取消移除。"
                    continue
                candidate[key] = [x for x in items if x not in selected]
                heading(LIST_TITLES[key] + " / 确认移除")
                print("  已选择 %d 项：\n" % len(selected))
                for item in sorted(selected):
                    print("    · " + item)
                if key == "ips":
                    overlaps = []
                    for address in sorted(selected):
                        reasons = matching_sources(candidate, address)
                        if reasons:
                            overlaps.append(address)
                            print("\n  %s 仍被其他名单放行：" % address)
                            for reason in reasons:
                                print("    · " + reason)
                    if overlaps:
                        print()
                        menu_table([(1, "彻底撤销访问权限", ""),
                                    (2, "只移除此处条目，保留其他放行", ""),
                                    (0, "取消", "")])
                        mode = read_choice("请选择移除方式：")
                        if mode == "1":
                            candidate = revoke_addresses(candidate, selected)
                        elif mode != "2":
                            message = "已取消移除。"
                            continue
                if key == "blocked_ips":
                    print("\n  解除禁止后，仍按白名单决定能否访问。")
                if not confirm("确认移除以上 %d 项？" % len(selected)):
                    message = "已取消移除。"
                    continue
            elif choice == "3":
                view_list(key)
                continue
            else:
                message = "请输入菜单中的编号。"
                continue
            message = save_from_menu(cfg, candidate)
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)


def check_address():
    heading("检查 IP 访问权限")
    raw = read_choice("请输入 IP，0 返回：")
    if raw in ("0", ""):
        return
    address = str(ipaddress.ip_address(raw))
    with operation_lock():
        state = read_state()
        current = state.get("current")
        if not current:
            raise AppError("暂无成功应用记录")
        cfg = current["config"]
        print("\n  检查结果：" + address)
        print("以下判断依据上次成功规则；其他防火墙或 Docker 转发规则需另行检查。")
        if not live_table():
            print("本程序过滤未启用。")
        elif address in cfg["blocked_ips"]:
            print("禁止访问：命中禁止列表。")
        else:
            # Evaluate recorded applied rules, not newer on-disk province caches.
            version = ipaddress.ip_address(address).version
            match = re.search(r"set allow%d \{(.*?)\n    \}" % version, current["rules"], re.S)
            elements = re.search(r"elements = \{ (.*?) \}", match.group(1)) if match else None
            networks = elements.group(1).split(", ") if elements else []
            permitted = (version == 6 and cfg["allow_all_ipv6"]) or any(
                ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in networks)
            print("业务入站：%s" % ("允许" if permitted else "拒绝（包括既有入站连接）"))
            print("配置/当前缓存中的覆盖线索（实际判定以上次生效规则为准）：")
            for reason in matching_sources(cfg, address):
                print("  · " + reason)
            if cfg["allow_ping"]:
                print("公网 ping 已开启：ping 通不代表业务端口可访问。")


def options_menu():
    message = ""
    while True:
        cfg = load_config()
        heading("访问设置")
        print("  选择一项即可切换。\n")
        menu_table([(1, "公网 ping", "允许" if cfg["allow_ping"] else "仅白名单"),
                    (2, "IPv6 访问", "全部放行" if cfg["allow_all_ipv6"] else "按白名单"),
                    (3, "Docker / 映射端口保护", "开启" if cfg["protect_dnat"] else "关闭"),
                    (0, "返回主菜单", "")])
        notice(message)
        choice = read_choice("请选择：")
        message = ""
        if choice == "0":
            return
        if not choice:
            continue
        key = {"1": "allow_ping", "2": "allow_all_ipv6", "3": "protect_dnat"}.get(choice)
        if not key:
            message = "请输入菜单中的编号。"
            continue
        try:
            candidate = copy.deepcopy(cfg)
            candidate[key] = not cfg[key]
            if key == "allow_all_ipv6" and candidate[key] and not confirm("全部 IPv6 来源将可访问业务端口（禁止列表除外）。继续？"):
                message = "已取消，设置未修改。"
                continue
            if key == "protect_dnat" and not candidate[key] and not confirm("映射端口将不再受本程序保护。继续？"):
                message = "已取消，设置未修改。"
                continue
            message = save_from_menu(cfg, candidate)
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)


def maintenance_menu():
    message = ""
    while True:
        heading("维护与日志")
        menu_table([(1, "查看运行状态", ""), (2, "刷新省份数据", ""),
                    (3, "恢复上一版配置", ""), (4, "查看最近日志", ""),
                    (0, "返回主菜单", "")])
        notice(message)
        choice = read_choice("请选择：")
        message = ""
        try:
            if choice == "0":
                return
            if choice == "":
                continue
            if choice == "1":
                heading("维护与日志 / 运行状态")
                status()
                pause()
            elif choice == "2":
                heading("维护与日志 / 刷新省份数据")
                print("\n  正在刷新省份数据，请稍候…", flush=True)
                apply_once(force_refresh=True)
                print("\n  刷新流程已完成。下载失败时会使用旧缓存，详情见上方输出。")
                pause()
            elif choice == "3":
                previous = read_state().get("previous")
                if not previous:
                    message = "暂无上一版配置。成功修改配置后即可使用。"
                    continue
                heading("维护与日志 / 恢复上一版")
                timestamp = previous.get("applied_at")
                if timestamp:
                    print("  备份时间：" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)))
                print("  将同时恢复当时的配置和访问权限。")
                if guard_session(previous["config"]) and confirm("确认恢复？"):
                    rollback()
                    message = "已恢复上一版配置和规则。"
                else:
                    message = "已取消恢复。"
            elif choice == "4":
                heading("维护与日志 / 最近日志")
                result = run(["journalctl", "-u", "vps-firewall", "-n", "40", "--no-pager"])
                print(result.stdout or result.stderr)
                pause()
            else:
                message = "请输入菜单中的编号。"
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)


def update_program(tag=None):
    command = [sys.executable, str(Path(__file__).with_name("github_install.py"))]
    if tag:
        command.extend(["--tag", tag])
    return subprocess.call(command)


def program_menu(action):
    heading(action)
    if action == "更新程序":
        print("  当前版本：" + APP_VERSION)
        print("  将检查并安装最新正式版本，保留现有配置和数据。")
        print("  完成后自动重新打开菜单。")
        if not confirm("确认更新程序？"):
            return None
        result = update_program()
        if result == 0:
            # Replace this process so the menu uses the newly installed code and version.
            os.execv(sys.executable, [sys.executable, "/opt/vps-firewall/vps_firewall.py", "menu"])
    else:
        print("  将停止防护，删除本程序的规则、服务和安装文件。")
        print("  配置、缓存和历史会先备份，备份位置将在卸载后显示。")
        if not confirm("确认卸载程序？"):
            return None
        result = subprocess.call(["bash", str(Path(__file__).with_name("uninstall.sh")), "--yes"])
    if result != 0:
        print("\n  %s未完成，请检查上方错误信息。菜单已退出。" % action)
    return result


def interactive_menu():
    message = ""
    while True:
        try:
            try:
                cfg = load_config()
            except (AppError, OSError, ValueError) as exc:
                heading("配置需要恢复")
                print("  配置无法读取：%s" % exc)
                current = read_state().get("current")
                if not current or not confirm("是否恢复最近一次成功配置？"):
                    return 1
                with operation_lock():
                    recover_pending()
                    current = read_state()["current"]
                    if not Path(CONFIG_PATH).exists():
                        atomic_write(CONFIG_PATH, dump_config(current["config"]))
                    commit(current["config"], current["rules"], save=True)
                message = "已恢复最近一次成功配置。"
                continue
            current = read_state().get("current")
            render_home(cfg, live_table(), ssh_source(),
                        bool(current and current["config"] == cfg), message)
            choice = read_choice("请选择：")
            message = ""
            if choice == "0":
                print("\n  已退出。防护保持当前状态。")
                return 0
            if choice == "":
                continue
            keys = {"2": "blocked_ips", "3": "rescue_ips"}
            if choice == "1":
                whitelist_menu()
            elif choice in keys:
                edit_list(keys[choice])
            elif choice == "4":
                check_address()
                pause()
            elif choice == "5":
                options_menu()
            elif choice == "6":
                maintenance_menu()
            elif choice == "7":
                candidate = copy.deepcopy(cfg)
                candidate["enabled"] = not cfg["enabled"]
                heading("暂停防护" if cfg["enabled"] else "开启防护")
                print("  " + ("暂停后，本程序将不再拦截入站访问。" if cfg["enabled"] else
                              "开启后，按当前白名单和禁止列表限制入站访问。"))
                if confirm("确认%s？" % ("暂停防护" if cfg["enabled"] else "开启防护")):
                    message = save_from_menu(cfg, candidate)
                else:
                    message = "已取消，防护状态未改变。"
            elif choice in ("8", "9"):
                action = "更新程序" if choice == "8" else "卸载程序"
                try:
                    result = program_menu(action)
                except OSError as exc:
                    print("\n  %s未完成：%s。菜单已退出。" % (action, exc))
                    return 1
                if result is not None:
                    return result
                message = "已取消%s。" % action
            else:
                message = "请输入 0 到 9 之间的编号。"
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)
            # Avoid an immediate redraw loop if reading configuration/firewall itself failed.
            print("\n  " + message)
            if read_choice("回车重试，0 退出：") == "0":
                return 1


def initialize(rescue):
    with operation_lock():
        if Path(CONFIG_PATH).exists():
            with open(CONFIG_PATH, "rb") as stream:
                existing = tomllib.load(stream)
            if existing.get("rescue_ips") or not existing.get("enabled", True):
                validate_config(existing)
                log("保留现有配置")
                return
            log("旧配置没有管理地址，需要补充后才能安全升级")
        else:
            existing = copy.deepcopy(DEFAULTS)
        addresses = split_values(rescue or "")
        source = ssh_source()
        if source and source not in addresses:
            addresses.append(source)
        if not addresses and sys.stdin.isatty():
            addresses = split_values(read_choice("请输入管理/抢救 IP（IPv4/IPv6，多个用空格分隔）："))
        if not addresses:
            raise AppError("无法确定管理 IP；请执行 sudo bash install.sh 你的管理IP")
        cfg = existing
        cfg["rescue_ips"] = addresses
        atomic_write(CONFIG_PATH, dump_config(cfg))
        log("初始管理地址：" + "、".join(addresses))


def migrate_legacy():
    """Restore only the recognizable system file generated by version 1."""
    with operation_lock():
        path = Path(SYSTEM_RULES_PATH)
        if not path.exists():
            return
        text = path.read_text(encoding="utf-8")
        stripped = text.strip()
        disabled = stripped == "# 白名单已停止：入站全部放行"
        old_header = re.match(r"flush table inet vps_wl\s+table inet vps_wl\s*\{", stripped)
        owned = False
        if old_header:
            # Require one complete table and no trailing commands: never discard mixed rules.
            depth = 1
            rest = stripped[old_header.end():]
            for index, char in enumerate(rest):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                if depth == 0:
                    owned = not rest[index + 1:].strip()
                    break
        if not owned and not disabled:
            if re.search(r"\b(?:table|include)\b[^\n]*vps_wl", text):
                raise AppError("/etc/nftables.conf 含自定义 vps_wl 规则，无法自动迁移；请先移除该表的持久化定义，保留其他规则")
            return
        atomic_write(Path(DATA_DIR) / "legacy-nftables.conf", text)
        original = Path(DATA_DIR) / "nftables.conf.orig"
        restored = original.read_text(encoding="utf-8") if original.exists() else "# vps-firewall由 vps-firewall.service 独立管理\n"
        if re.search(r"\btable\s+inet\s+vps_wl\b", restored):
            raise AppError("旧版原始备份仍含 vps_wl 表，无法安全自动恢复；备份已保留，请先检查 /etc/nftables.conf")
        atomic_write(path, restored)
        log("旧版系统规则文件已迁移；原文件另存为 legacy-nftables.conf")


def main():
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(prog="vps-firewall", description="vps-firewall；无参数直接进入中文菜单")
    parser.add_argument("--version", action="version", version="%(prog)s " + APP_VERSION,
                        help="显示当前程序版本并退出")
    parser.add_argument("command", nargs="?", default="menu",
                        choices=["menu", "config", "apply", "reload", "daemon", "status",
                                 "rollback", "test", "check", "init", "migrate", "boot",
                                 "version", "update"])
    parser.add_argument("--force", action="store_true", help="强制刷新省份数据")
    parser.add_argument("--rescue", default="", help="首次安装的管理 IP，多个用逗号分隔")
    parser.add_argument("--tag", help="update 指定正式版本，例如 v1.0.0")
    args = parser.parse_args()
    if args.tag and args.command != "update":
        parser.error("--tag 仅用于 update")
    try:
        if args.command == "version":
            print("vps-firewall " + APP_VERSION)
            return 0
        if sys.platform != "linux":
            raise AppError("运行防火墙需 Debian 12/13；当前系统仅可进行源码测试")
        if os.geteuid() != 0:
            raise AppError("请使用 sudo vps-firewall 运行")
        if args.command == "update":
            return update_program(args.tag)
        elif args.command == "init":
            initialize(args.rescue)
        elif args.command == "migrate":
            migrate_legacy()
        elif args.command == "boot":
            boot()
        elif args.command in ("menu", "config"):
            return interactive_menu()
        elif args.command == "daemon":
            daemon()
        elif args.command == "status":
            status()
        elif args.command == "rollback":
            rollback()
        else:
            apply_once(dry_run=args.command in ("test", "check"), force_refresh=args.force)
        return 0
    except (AppError, OSError, ValueError) as exc:
        print("错误：" + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已取消。")
        return 130


if __name__ == "__main__":
    sys.exit(main())
