#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Debian 12/13 vps-firewall。只管理 ip vps_wl 表（仅 IPv4），不改系统 nftables.conf。

IPv6 流量不经过本程序：既不放行也不拦截，由系统其他防火墙或云安全组决定。
"""
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
APP_RELEASE_DATE = "2026.09.30"
# HTTP headers must stay ASCII; the fallback version text ("未知") is not.
USER_AGENT = "vps-firewall/" + APP_VERSION if re.fullmatch(r"[0-9A-Za-z.+-]+", APP_VERSION) else "vps-firewall"

CONFIG_PATH = "/etc/vps-firewall/config.toml"
DATA_DIR = "/var/lib/vps-firewall"
CACHE_DIR = DATA_DIR + "/province_cache"
STATE_PATH = DATA_DIR + "/state.json"
SYSTEM_RULES_PATH = "/etc/nftables.conf"
LOCK_PATH = "/run/lock/vps-firewall.lock"
TABLE = "vps_wl"
# 1.3.0 起只过滤 IPv4，规则表为 ip 族；1.2 及更早版本用 inet 族（同时过滤 IPv6）。
FAMILY = "ip"
LEGACY_FAMILY = "inet"
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
                blocked_ips=[], ping_mode="whitelist", protect_dnat=True,
                watch_interval=5, province_refresh=86400, province_source_base="", notes={}, paused={})
# 公网 Ping 三档：off 任何来源都不可 ping；whitelist 仅白名单可 ping；all 任何来源都可 ping。
PING_MODES = ("off", "whitelist", "all")
# 1.2.0 之前的布尔开关：true = all，false = whitelist；读取时自动换算，保存时写成 ping_mode。
LEGACY_PING_KEY = "allow_ping"
# 1.3.0 之前的“IPv6 全部放行”开关；读取时忽略，保存时不再写出。
LEGACY_IPV6_KEY = "allow_all_ipv6"
LABELS = dict(rescue_ips="直通 IP（管理地址）", provinces="省份白名单",
              cidrs="网段白名单", ips="IP 白名单", blocked_ips="禁止 IP")
LIST_KEYS = tuple(LABELS)
NOTE_KEYS = ("ips", "cidrs", "provinces")


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
    except ValueError as exc:
        raise AppError("无效 IP 或网段：%s" % value) from exc
    if obj.version != 4:
        raise AppError("本程序只过滤 IPv4，不支持 IPv6 地址：%s" % value)
    return str(obj)


def is_ipv6(value):
    try:
        value = str(value).strip()
        obj = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    except ValueError:
        return False
    return obj.version == 6


def strip_ipv6(raw):
    """去掉旧配置中的 IPv6 内容，返回 (配置, 被清除内容的说明列表)。

    1.3.0 起 IPv6 流量不经过本程序，这些条目不再有任何作用；其他非法内容留给 validate_config 报错。
    """
    raw = dict(raw)
    removed = []
    if raw.pop(LEGACY_IPV6_KEY, None) is True:
        removed.append("IPv6 全部放行开关")
    for key in ("rescue_ips", "cidrs", "ips", "blocked_ips"):
        if isinstance(raw.get(key), list):
            removed += ["%s %s" % (LABELS[key], item) for item in raw[key] if is_ipv6(item)]
            raw[key] = [item for item in raw[key] if not is_ipv6(item)]
    for section in ("notes", "paused"):
        if isinstance(raw.get(section), dict):
            groups = dict(raw[section])
            for key in ("cidrs", "ips"):
                if isinstance(groups.get(key), dict):
                    groups[key] = {item: note for item, note in groups[key].items() if not is_ipv6(item)}
                elif isinstance(groups.get(key), list):
                    groups[key] = [item for item in groups[key] if not is_ipv6(item)]
            raw[section] = groups
    return raw, removed


def resolve_province_code(name):
    return PROVINCE_CODES.get(str(name).strip())


def normalize_entry(key, item):
    if key == "provinces":
        code = resolve_province_code(item)
        if not code:
            raise AppError("未知省份：%s" % item)
        return next(n for n in PROVINCE_NAMES if PROVINCE_CODES[n] == code)
    return norm(item)


def validate_note(value):
    if not isinstance(value, str):
        raise AppError("备注必须是文字")
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise AppError("备注不能包含换行或控制字符")
    value = value.strip()
    if len(value) > 120:
        raise AppError("备注最多 120 个字符")
    return value


def validate_config(raw):
    raw, removed = strip_ipv6(raw)
    if LEGACY_PING_KEY in raw:
        legacy = raw.pop(LEGACY_PING_KEY)
        if "ping_mode" in raw:
            raise AppError("allow_ping 与 ping_mode 不能同时设置；请删除旧的 allow_ping")
        if type(legacy) is not bool:
            raise AppError("allow_ping 必须为 true 或 false")
        raw["ping_mode"] = "all" if legacy else "whitelist"
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise AppError("不支持的配置项：%s" % ", ".join(sorted(unknown)))
    cfg = copy.deepcopy(DEFAULTS)
    cfg.update(raw)
    for key in ("enabled", "protect_dnat"):
        if type(cfg[key]) is not bool:
            raise AppError("%s 必须为 true 或 false" % key)
    if cfg["ping_mode"] not in PING_MODES:
        raise AppError("ping_mode 只能是 %s" % " / ".join('"%s"' % mode for mode in PING_MODES))
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
            value = normalize_entry(key, item)
            if key in ("ips", "blocked_ips") and "/" in value:
                raise AppError("%s 只接受单 IP；网段请放到网段白名单" % LABELS[key])
            if value not in entries:
                entries.append(value)
        cfg[key] = entries
    if not isinstance(cfg["notes"], dict) or set(cfg["notes"]) - set(NOTE_KEYS):
        raise AppError("备注仅支持 ips、cidrs、provinces 分类")
    notes = {}
    for key, entries in cfg["notes"].items():
        if not isinstance(entries, dict):
            raise AppError("%s 备注必须是条目与文字的对应表" % key)
        for item, value in entries.items():
            if not isinstance(item, str):
                raise AppError("备注条目必须是字符串")
            item = normalize_entry(key, item)
            value = validate_note(value)
            if item in cfg[key] and value:
                group = notes.setdefault(key, {})
                if item in group and group[item] != value:
                    raise AppError("同一条目的备注冲突：" + item)
                group[item] = value
    cfg["notes"] = notes
    if not isinstance(cfg["paused"], dict) or set(cfg["paused"]) - set(NOTE_KEYS):
        raise AppError("暂停条目仅支持 ips、cidrs、provinces 分类")
    paused = {}
    for key, entries in cfg["paused"].items():
        if not isinstance(entries, list) or not all(isinstance(item, str) for item in entries):
            raise AppError("%s 暂停条目必须是字符串数组" % key)
        normalized = {normalize_entry(key, item) for item in entries}
        retained = [item for item in cfg[key] if item in normalized]
        if retained:
            paused[key] = retained
    cfg["paused"] = paused
    if cfg["enabled"] and not cfg["rescue_ips"]:
        if any(text.startswith(LABELS["rescue_ips"]) for text in removed):
            raise AppError("管理/抢救地址只有 IPv6，而本程序只过滤 IPv4；请先在配置中添加一个 IPv4 管理地址")
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


def ipv6_leftovers(path=None):
    """配置文件里仍写着、但已被忽略的 IPv6 内容；用于提示并在下次应用时从文件中清除。"""
    if tomllib is None:
        raise AppError("需要 Python 3.11 或更高版本")
    with open(path or CONFIG_PATH, "rb") as stream:
        return strip_ipv6(tomllib.load(stream))[1]


def dump_config(cfg):
    cfg = validate_config(cfg)
    lines = ["# vps-firewall配置；手动修改后自动重载。菜单保存会重新整理格式。",
             "# 白名单取并集；禁止访问优先；管理地址不得与禁止地址重叠。"]
    for key in DEFAULTS:
        if key in ("notes", "paused"):
            if not cfg[key]:
                lines.append(key + " = {}")
            continue
        value = cfg[key]
        if key in LABELS:
            lines.append("\n# " + LABELS[key])
        elif key == "ping_mode":
            lines.append("\n# 公网 Ping：\"off\" 全部禁止 / \"whitelist\" 仅白名单 / \"all\" 所有人")
        # JSON strings, lists and booleans are valid for this TOML schema.
        lines.append(key + " = " + json.dumps(value, ensure_ascii=False))
    if cfg["paused"]:
        lines.append("\n[paused]")
        for key, entries in cfg["paused"].items():
            lines.append(key + " = " + json.dumps(entries, ensure_ascii=False))
    for key in NOTE_KEYS:
        entries = cfg["notes"].get(key, {})
        if entries:
            lines.append("\n[notes.%s]" % key)
            for item, note in entries.items():
                lines.append(json.dumps(item, ensure_ascii=False) + " = " + json.dumps(note, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def config_sig():
    return hashlib.sha256(Path(CONFIG_PATH).read_bytes()).hexdigest()


def parse_province(data):
    networks = set()
    for line in data.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if is_ipv6(line):
            raise AppError("省份数据包含非 IPv4 地址")
        networks.add(norm(line))
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
                    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
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


def active_entries(cfg, key):
    paused = set(cfg.get("paused", {}).get(key, ()))
    return [item for item in cfg[key] if item not in paused]


def build_allowlist(cfg, force_refresh=False, write_cache=True):
    allow = set(cfg["rescue_ips"] + active_entries(cfg, "cidrs") + active_entries(cfg, "ips"))
    provinces = active_entries(cfg, "provinces")
    if provinces:
        bases = ([cfg["province_source_base"]] if cfg["province_source_base"] else []) + DEFAULT_PROVINCE_BASES
        allow.update(fetch_provinces(provinces, cfg["province_refresh"], bases,
                                    force=force_refresh, write_cache=write_cache))
    # No runtime SSH discovery: a removed address must never silently return.
    return allow


def collapse(entries):
    nets = [ipaddress.ip_network(x, strict=False) for x in entries]
    return [str(n) for n in ipaddress.collapse_addresses(n for n in nets if n.version == 4)]


def reset_lines():
    """删除本程序的表。"add table" 在表已存在时也成功，因此整段可放进同一个原子事务。

    同时删除 1.2 及更早版本的 inet 表：否则升级后它会继续拦截 IPv6，并与新表重复过滤 IPv4。
    """
    lines = []
    for family in (LEGACY_FAMILY, FAMILY):
        lines += ["add table %s %s" % (family, TABLE), "delete table %s %s" % (family, TABLE)]
    return lines


def legacy_rules(rules):
    """1.2 及更早版本保存的规则文本（inet 表，含 IPv6 规则）；不能再原样恢复。"""
    return ("add table %s %s\n" % (FAMILY, TABLE)) not in rules


def render_rules(allowlist, ping_mode="whitelist", blocked_ips=(), enabled=True, protect_dnat=True):
    if ping_mode not in PING_MODES:
        raise AppError("未知的 ping 模式：%s" % ping_mode)
    # One atomic nft transaction. The ip family only sees IPv4; IPv6 never reaches this table.
    lines = reset_lines()
    if not enabled:
        return "\n".join(lines) + "\n"
    lines.append("table %s %s {" % (FAMILY, TABLE))
    for prefix, entries in (("allow", allowlist), ("blocked", blocked_ips)):
        values = collapse(entries)
        lines += ["    set %s4 {" % prefix, "        type ipv4_addr", "        flags interval"]
        if values:
            lines.append("        elements = { " + ", ".join(values) + " }")
        lines.append("    }")
    lines += ["    chain input {",
              "        type filter hook input priority 10; policy drop;",
              '        iifname "lo" accept',
              "        ct state invalid drop",
              "        ip saddr @blocked4 counter drop",
              # Only replies to connections originated by this VPS bypass source membership.
              "        ct direction reply ct state established,related accept",
              "        ct state related meta l4proto icmp accept"]
    # Echo requests are decided before the allow set: "off" must also beat the whitelist.
    # Loopback is accepted above, so the host can still ping itself.
    if ping_mode == "all":
        lines.append("        icmp type echo-request accept")
    elif ping_mode == "off":
        lines.append("        icmp type echo-request counter drop")
    lines += ["        ip saddr @allow4 accept", "        counter drop", "    }"]
    if protect_dnat:
        # Published Docker/NAT ports traverse forward instead of input.
        # Scope to DNAT original direction; ordinary routing and container egress stay untouched.
        lines += ["    chain published {", "        ip saddr @blocked4 counter drop",
                  "        ip saddr @allow4 accept",
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


def live_families():
    """本程序的表当前以哪些地址族存在；升级后首次应用前可能还留着旧的 inet 表。"""
    result = run(["nft", "-j", "list", "tables"])
    if result.returncode:
        raise AppError("无法读取防火墙：" + result.stderr.strip())
    tables = [x.get("table", {}) for x in json.loads(result.stdout).get("nftables", [])]
    return [family for family in (LEGACY_FAMILY, FAMILY)
            if any(x.get("family") == family and x.get("name") == TABLE for x in tables)]


def live_table():
    return FAMILY in live_families()


def live_snapshot():
    text = render_rules([], enabled=False)
    for family in live_families():
        result = run(["nft", "list", "table", family, TABLE])
        if result.returncode:
            raise AppError("无法备份当前白名单规则：" + result.stderr.strip())
        text += result.stdout
    return text


def read_state():
    if not Path(STATE_PATH).exists():
        return {}
    try:
        state = json.loads(Path(STATE_PATH).read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise AppError("运行状态文件无法读取：" + str(exc)) from exc
    # 旧版记录换算成当前格式（allow_ping → ping_mode，去掉 IPv6 内容），
    # 这样升级后不会仅因格式不同被判为“未同步”。
    for record in (state.get("current"), state.get("previous")) if isinstance(state, dict) else ():
        if not isinstance(record, dict) or not isinstance(record.get("config"), dict):
            continue
        saved = strip_ipv6(record["config"])[0]
        if type(saved.get(LEGACY_PING_KEY)) is bool and "ping_mode" not in saved:
            saved["ping_mode"] = "all" if saved.pop(LEGACY_PING_KEY) else "whitelist"
        record["config"] = saved
    return state


def record_policy(record):
    """成功记录中的 (配置, 规则)。旧版记录的规则是 inet 表，改按其配置重新生成。"""
    cfg = validate_config(record["config"])
    return cfg, (prepare(cfg) if legacy_rules(record["rules"]) else record["rules"])


def prepare(cfg, force=False, dry_run=False):
    cfg = validate_config(cfg)
    allow = build_allowlist(cfg, force, write_cache=not dry_run) if cfg["enabled"] else set()
    return render_rules(allow, cfg["ping_mode"], cfg["blocked_ips"], cfg["enabled"], cfg["protect_dnat"])


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
        leftovers = ipv6_leftovers()
        rules = prepare(cfg, force_refresh, dry_run)
        if config_sig() != signature:
            raise AppError("处理期间配置文件发生变化，请重试")
        if dry_run:
            nft(rules, check=True)
            log("配置和规则校验通过；未修改防火墙、配置或缓存")
            if leftovers:
                log("本程序只过滤 IPv4；应用时将从配置中清除：" + "、".join(leftovers))
        else:
            # 配置里残留的 IPv6 内容已不起作用：随本次应用一并从文件中清除。
            commit(cfg, rules, save=bool(leftovers))
            if leftovers:
                log("本程序只过滤 IPv4，IPv6 流量不受本程序限制；已从配置中清除：" + "、".join(leftovers))
                return config_sig()
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
        # Restore exact prior own-table rules, including prior province contents.
        cfg, rules = record_policy(previous)
        commit(cfg, rules, save=True, state=state)
    log("已恢复上一版配置及本程序规则；其他防火墙规则不受影响")


def boot():
    # No network fetch needed to restore a successfully applied policy after reboot.
    with operation_lock():
        recover_pending()
        current = read_state().get("current")
        # 旧版记录的规则是 inet 表，不再原样恢复，交给下面的 apply_once 重新生成。
        if current and not legacy_rules(current["rules"]):
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
            apply_required = False
            with operation_lock():
                recover_pending()
                cfg = load_config()
                watch = cfg["watch_interval"]
                sig = config_sig()
                current = read_state().get("current")
                unsynced = (not current or current["config"] != cfg or legacy_rules(current["rules"])
                            or bool(ipv6_leftovers()))
                refresh = cfg["province_refresh"]
                due = (cfg["enabled"] and bool(active_entries(cfg, "provinces")) and refresh > 0
                       and time.monotonic() - last_refresh >= refresh)
                missing = live_table() != cfg["enabled"]
                if (sig != last_sig or due or missing or unsynced) and time.monotonic() >= retry_at:
                    if not due and not unsynced:
                        # Recover the committed policy without downloads or replacing rollback history.
                        if missing:
                            nft(current["rules"], check=True)
                            nft(current["rules"])
                            log("检测到实际规则与保存的开关不一致，已恢复上次成功规则；若反复出现，请检查旧版服务或其他防火墙程序")
                        last_sig = sig
                        retry_at = 0
                    else:
                        reason = "省份数据定时刷新" if due else "配置与成功记录不同、尚无成功记录或需要升级旧版内容"
                        log("重新应用原因：" + reason)
                        apply_required = True
            if apply_required:
                # apply_once re-reads configuration under its own lock; never apply a stale menu snapshot.
                last_sig = apply_once(force_refresh=due)
                last_refresh = time.monotonic()
                retry_at = 0
        except Exception as exc:
            log("未应用：%s；稍后重试" % exc)
            retry_at = time.monotonic() + 15
        time.sleep(watch)


def ssh_source():
    # SSH_CONNECTION includes custom SSH ports without port-specific probing.
    # The result may be an IPv6 address; callers must not treat it as a filterable source.
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
            address = ipaddress.ip_address(value[0])
        except ValueError:
            continue
        return str(getattr(address, "ipv4_mapped", None) or address)
    return None


def matching_sources(cfg, address, use_cache=True):
    ip = ipaddress.ip_address(address)
    reasons = []
    for key in ("rescue_ips", "ips", "cidrs"):
        for item in active_entries(cfg, key):
            if ip in ipaddress.ip_network(item, strict=False):
                reasons.append("%s：%s" % (LABELS[key], item))
    if use_cache:
        for name in active_entries(cfg, "provinces"):
            path = Path(CACHE_DIR) / (resolve_province_code(name) + ".txt")
            if not path.exists():
                log("省份 %s 缓存缺失，无法确认其是否覆盖该 IP" % name)
                continue
            networks = parse_province(path.read_text(encoding="utf-8"))
            if any(ip in ipaddress.ip_network(n, strict=False) for n in networks):
                reasons.append("省份白名单：" + name)
    return reasons


def status():
    with operation_lock():
        cfg = load_config()
        state = read_state()
        active = live_table()
        service = run(["systemctl", "is-active", "vps-firewall"]).stdout.strip()
        legacy = run(["systemctl", "is-active", "vps-whitelist"]).stdout.strip() == "active"
        current = state.get("current")
        synced = bool(current and current["config"] == cfg)
        lines = [field_text("程序版本", "vps-firewall %s（%s）" % (APP_VERSION, APP_RELEASE_DATE)),
                 field_text("防护状态", protection_badge(cfg, active) + "  " + protection_status(cfg, active)),
                 field_text("保存的开关", "开启" if cfg["enabled"] else "关闭"),
                 field_text("实际规则表", "存在" if active else "缺失"),
                 field_text("后台服务", {"active": style("● 运行中", "green"),
                                         "inactive": style("○ 未运行", "red"),
                                         "failed": style("✖ 启动失败", "red")}.get(service, service or "未知")),
                 field_text("配置同步", sync_badge(synced))]
        if current:
            lines.append(field_text("最近生效", time.strftime("%Y-%m-%d %H:%M:%S",
                                                              time.localtime(current["applied_at"]))))
        print()
        card("运行", lines)
        if legacy:
            card("服务冲突", [style("✖ 旧版 vps-whitelist 仍在运行，可能覆盖同一张规则表。", "red"),
                              style("请升级以停用本项目的旧服务，或先执行 sudo systemctl disable --now vps-whitelist。",
                                    "dim")])
        card("开关", [field_text("公网 Ping", ping_badge(cfg["ping_mode"])),
                      field_text(OPTION_TEXT["protect_dnat"][0], option_badge("protect_dnat", cfg["protect_dnat"])),
                      field_text("IPv6", style("不经过本程序，不放行也不拦截", "dim"))])
        for key in WHITELIST_KEYS + ("blocked_ips", "rescue_ips"):
            card("%s · %d 项" % (LIST_TITLES[key], len(cfg[key])), entry_lines(cfg, key))
        return cfg


# ── 终端界面 ────────────────────────────────────────────────────────────
# 纯标准库。每页由三层组成：
#   双线横幅（位置面包屑 + 版本 / 状态）→ 圆角卡片（按功能分区的编号操作）→ 底部返回键、结果提示、输入行。
# 配色见 COLORS；颜色和清屏只在交互终端启用；重定向输出或 NO_COLOR 时为纯文本，宽度按中文显示宽度对齐。
PAGE_SIZE = 12
LABEL_WIDTH = 14
APP_TITLE = "vps-firewall"
WHITELIST_KEYS = ("ips", "cidrs", "provinces")
LIST_TITLES = {
    "ips": "IP 白名单",
    "cidrs": "网段白名单",
    "provinces": "省份白名单",
    "blocked_ips": "禁止 IP",
    "rescue_ips": "直通 IP",
}
LIST_HINTS = {
    "ips": "放行单个 IPv4 地址。",
    "cidrs": "放行整个 IPv4 网段。",
    "provinces": "放行所选省份的 IPv4 地址；归属数据来自外部数据源。",
    "blocked_ips": "禁止优先于所有白名单；不能与直通 IP 重叠；仅 IPv4。",
    "rescue_ips": "管理登录专用地址；开启防护时至少保留一个。",
}
LIST_EXAMPLES = {
    "ips": ("203.0.113.10   198.51.100.20", "请输入 IP："),
    "cidrs": ("203.0.113.0/24   198.51.100.0/25", "请输入网段："),
    "blocked_ips": ("198.51.100.7   198.51.100.8", "请输入要禁止的 IP："),
    "rescue_ips": ("203.0.113.10   203.0.113.0/24", "请输入 IP 或网段："),
}
OPTION_TEXT = {
    # key: (名称, 说明)
    "protect_dnat": ("映射端口保护", "Docker / NAT 映射端口使用同一白名单；不影响普通路由转发。"),
}
# ping 模式：(名称, 说明)
PING_TEXT = {
    "off": ("全部禁止", "任何来源都不可 ping 本机，包括白名单和直通 IP"),
    "whitelist": ("仅白名单", "仅白名单和直通 IP 可 ping 本机"),
    "all": ("所有人", "任何来源都可 ping 本机，禁止 IP 除外"),
}
PING_ALIASES = {"off": "off", "whitelist": "whitelist", "all": "all", "on": "all"}
ANSI_RE = re.compile(r"\033\[[0-9;]*m")
TOKEN_RE = re.compile(r"\033\[[0-9;]*m|.", re.S)
NO_LINE_START = set("，。、；：！？）」”》,.;:!?)")
# 配色：白色（不着色）= 功能文字；灰色 dim = 说明与边框；绿色 = 开启 / 启用 / 成功；红色 = 关闭 / 暂停 / 失败。
COLORS = dict(bold="1", dim="2", red="31", green="32")


def interactive_terminal():
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


def style(text, *names):
    text = str(text)
    if not names or not interactive_terminal() or os.environ.get("NO_COLOR"):
        return text
    return "\033[%sm%s\033[0m" % (";".join(COLORS[name] for name in names), text)


def display_width(text):
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
               for char in ANSI_RE.sub("", str(text)))


def pad(text, width):
    return str(text) + " " * max(0, width - display_width(text))


def ui_width():
    """卡片外框总宽度。"""
    return max(46, min(68, shutil.get_terminal_size((80, 24)).columns - 4))


def box_inner():
    return ui_width() - 6


def wrap_cell(text, width):
    """按显示宽度折行；保留颜色，折行处先复位再在下一行重新着色；标点不落在行首。"""
    lines = []
    for paragraph in str(text).split("\n"):
        line, used, active = [], 0, ""
        for token in TOKEN_RE.findall(paragraph):
            if token.startswith("\033"):
                line.append(token)
                active = "" if token == "\033[0m" else active + token
                continue
            size = display_width(token)
            if used and used + size > width:
                carry = []
                if token in NO_LINE_START and len(line) > 1 and not line[-1].startswith("\033"):
                    carry = [line.pop()]
                lines.append("".join(line) + ("\033[0m" if active else ""))
                line = ([active] if active else []) + carry
                used = sum(display_width(x) for x in carry)
            line.append(token)
            used += size
        lines.append("".join(line))
    return lines


def justify(left, right, width):
    """左右两端对齐；放不下时右侧内容右对齐另起一行。"""
    if not right:
        return [left]
    gap = width - display_width(left) - display_width(right)
    if gap >= 2:
        return [left + " " * gap + right]
    return [left, " " * max(0, width - display_width(right)) + right]


def key_text(key):
    return style(key, "bold")


def clear_screen():
    # Clear only an interactive screen, preserving scrollback and readable redirected output.
    if interactive_terminal():
        print("\033[2J\033[H", end="")


def frame(title, lines, corners):
    """外框绘制：lines 中的 None 画分隔线。corners 依次为 左上 横 右上 竖 左下 右下。"""
    top_left, horizontal, top_right, vertical, bottom_left, bottom_right = corners
    width, inner = ui_width(), box_inner()
    label = " %s " % title if title else ""
    print("  " + style(top_left + horizontal, "dim") + style(label, "bold") +
          style(horizontal * (width - 3 - display_width(label)) + top_right, "dim"))
    side = style(vertical, "dim")
    for line in lines:
        if line is None:
            print("  " + side + "  " + style("─" * inner, "dim") + "  " + side)
            continue
        for part in wrap_cell(line, inner):
            print("  " + side + "  " + pad(part, inner) + "  " + side)
    print("  " + style(bottom_left + horizontal * (width - 2) + bottom_right, "dim"))


def banner(lines):
    """页面顶部的双线横幅。"""
    frame("", lines, "╔═╗║╚╝")


def card(title, lines):
    """功能分区卡片：标题嵌在上边框里。"""
    frame(title, lines or [style("暂无", "dim")], "╭─╮│╰╯")


def heading(title="", *hints):
    """清屏后显示横幅：面包屑（用“ / ”分级）+ 版本号 + 灰色说明。"""
    clear_screen()
    print()
    crumbs = " › ".join([APP_TITLE] + [part for part in title.split(" / ") if part])
    banner(justify(style(crumbs, "bold"), style("v" + APP_VERSION, "dim"), box_inner()) +
           [style(text, "dim") for text in hints])
    print()


def hint(text):
    print("  " + style(text, "dim"))


def field_text(label, value):
    return pad(label, max(14, display_width(label) + 2)) + str(value)


def option_lines(rows, below=False):
    """编号操作行：(编号, 名称[, 说明[, 右侧状态]])。

    说明默认与名称同行（灰色），放不下或 below=True 时另起一行；状态始终靠右。
    """
    inner = box_inner()
    rows = [(tuple(row) + ("", "", ""))[:4] for row in rows]
    # 同一卡片内说明列对齐到最长名称之后。
    column = max([3 + LABEL_WIDTH] + [len(str(key)) + 4 + display_width(label)
                                      for key, label, note, _ in rows if note])
    # 任意一行放不下时，整张卡片统一改为说明另起一行，保持版式一致。
    below = below or any(column + display_width(note) + (display_width(right) + 2 if right else 0) > inner
                         for key, label, note, right in rows if note)
    lines = []
    for key, label, note, right in rows:
        head = key_text(str(key)) + "  " + label
        if note and not below:
            lines += justify(pad(head, column) + style(note, "dim"), right, inner)
            continue
        lines += justify(head, right, inner)
        if note:
            lines += ["   " + style(part, "dim") for part in wrap_cell(note, inner - 3)]
    return lines


def footer(*items):
    """卡片下方的返回/退出等键位，与卡片内容左对齐。"""
    print("     " + "      ".join(key_text(key) + "  " + label if key else style(label, "dim")
                                   for key, label in items))


def table(rows, headers=None):
    """圆角表格：2 列（编号 / 条目）或 4 列（编号 / 条目 / 状态 / 备注）。

    中文按显示宽度对齐，长地址和备注折行而不截断。
    """
    rows = [tuple(str(cell) for cell in row) for row in rows]
    width = ui_width()
    if len(rows[0]) == 2:
        widths = [4, width - 11]
    else:
        available = width - 23
        widths = [4, available // 2, 6, available - available // 2]

    def border(left, middle, right):
        print("  " + style(left + middle.join("─" * (column + 2) for column in widths) + right, "dim"))

    def line(cells):
        wrapped = [wrap_cell(cell, column) for cell, column in zip(cells, widths)]
        side = style("│", "dim")
        for index in range(max(map(len, wrapped))):
            values = [parts[index] if index < len(parts) else "" for parts in wrapped]
            print("  " + side + side.join(" " + pad(value, column) + " "
                                          for value, column in zip(values, widths)) + side)

    border("╭", "┬", "╮")
    if headers:
        line([style(cell, "bold") for cell in headers])
        border("├", "┼", "┤")
    for cells in rows:
        line(cells)
    border("╰", "┴", "╯")


def notice(message):
    if not message:
        return
    if message.startswith(("操作未完成", "错误")) or "未完成" in message:
        mark, color = "✖", "red"
    elif message.startswith(("已保存", "已恢复", "已生效", "已按", "刷新")):
        mark, color = "✔", "green"
    else:
        mark, color = "ℹ", "dim"
    print("\n  " + style(mark + " " + message, color))


def read_choice(prompt):
    try:
        return input("\n  " + key_text("›") + " " + prompt + " ").strip()
    except (EOFError, KeyboardInterrupt):
        return "0"


def pause():
    read_choice("按回车返回：")


def confirm(message):
    print()
    card("请确认", [message])
    footer(("1", "确认"), ("0", "取消（默认）"))
    return read_choice("请选择：").lower() in ("1", "y")


def count_text(number):
    return "%d 项" % number


def firewall_label(cfg, active):
    if cfg["enabled"] != active:
        return "未生效" if cfg["enabled"] else "未关闭"
    return "开启" if active else "关闭"


def protection_status(cfg, active):
    return {"开启": "已开启", "关闭": "已关闭", "未生效": "未生效（设置开启，但实际规则缺失）",
            "未关闭": "未关闭（设置关闭，但实际规则仍存在）"}[firewall_label(cfg, active)]


def protection_action(cfg, active):
    if cfg["enabled"] != active:
        return "恢复防护" if cfg["enabled"] else "关闭残留规则"
    return "暂停防护" if cfg["enabled"] else "开启防护"


def protection_badge(cfg, active):
    mark, text, color = {"开启": ("●", "防护中", "green"), "关闭": ("○", "已暂停", "red"),
                         "未生效": ("▲", "未生效", "red"), "未关闭": ("▲", "未关闭", "red")
                         }[firewall_label(cfg, active)]
    return style(mark + " " + text, "bold", color)


def sync_badge(synced):
    return style("✔ 已同步", "green") if synced else style("✖ 未同步", "red") + style("  请到“维护与日志”检查", "dim")


def switch_text(value, on="已开启", off="已关闭"):
    """开关状态：开启为绿色 ●，关闭为红色 ○。"""
    return style("● " + on, "green") if value else style("○ " + off, "red")


def option_badge(key, value):
    return switch_text(value)


def ping_badge(mode):
    """ping 模式：有来源可 ping 为绿色 ●，全部禁止为红色 ○。"""
    label = PING_TEXT[mode][0]
    return style("○ " + label, "red") if mode == "off" else style("● " + label, "green")


def ping_summary(mode):
    return "公网 Ping：%s，%s" % PING_TEXT[mode]


def entry_state(item, paused):
    return switch_text(item not in paused, on="启用", off="暂停")


def entry_lines(cfg, key, limit=None, empty="暂无条目"):
    """卡片中的条目预览：条目 + 灰色备注，白名单三类在右侧显示启用 / 暂停。"""
    items = cfg[key]
    if not items:
        return [style(empty, "dim")]
    notes = cfg["notes"].get(key, {})
    paused = set(cfg["paused"].get(key, ()))
    shown = items if limit is None else items[:limit]
    # 备注对齐成一列；超长条目只保留两个空格间隔。
    column = min(max(display_width(item) for item in shown), box_inner() // 2)
    lines = []
    for item in shown:
        text = "• " + (pad(item, column) + "  " + style(notes[item], "dim") if item in notes else item)
        lines += justify(text, entry_state(item, paused) if key in NOTE_KEYS else "", box_inner())
    if limit is not None and len(items) > limit:
        lines.append(style("… 还有 %d 项，选择“管理条目”查看全部" % (len(items) - limit), "dim"))
    return lines


def render_home(cfg, active, source=None, synced=True, message=""):
    inner = box_inner()
    mismatch = cfg["enabled"] != active
    clear_screen()
    print()
    banner(justify(style(APP_TITLE, "bold") + style("  v%s · %s" % (APP_VERSION, APP_RELEASE_DATE), "dim"),
                   protection_badge(cfg, active), inner) +
           [None] +
           justify(pad("登录 IP", 10) + (source or style("未检测到", "dim")),
                   "配置 " + sync_badge(synced), inner))
    if mismatch:
        print("\n  " + style("▲ 保存的开关与实际规则不一致", "red") +
              style("  请按 4 选择“%s”，或到“维护与日志”查看运行状态。" % protection_action(cfg, active), "dim"))
    print()
    counts = [len(cfg[key]) for key in WHITELIST_KEYS]
    paused = sum(len(cfg["paused"].get(key, ())) for key in WHITELIST_KEYS)
    card("名单管理", option_lines([
        (1, "白名单", "IP %d · 网段 %d · 省份 %d" % tuple(counts) + (" · 暂停 %d" % paused if paused else ""),
         count_text(sum(counts))),
        (2, "禁止 IP", "优先于所有白名单", count_text(len(cfg["blocked_ips"]))),
        (3, "直通 IP", "管理登录专用，至少保留一个", count_text(len(cfg["rescue_ips"]))),
    ]))
    if mismatch:
        switch = (4, protection_action(cfg, active), "按保存的开关重新应用规则", protection_badge(cfg, active))
    else:
        switch = (4, "防护总开关", "按名单拦截入站访问" if cfg["enabled"] else "当前不拦截入站访问",
                  switch_text(cfg["enabled"], off="已暂停"))
    card("快捷开关", option_lines([
        switch,
        (5, "公网 Ping", {"off": "任何来源都不可 ping", "whitelist": "仅白名单可 ping",
                          "all": "任何来源都可 ping"}[cfg["ping_mode"]],
         ping_badge(cfg["ping_mode"])),
    ]))
    card("工具", option_lines([
        (6, "检查 IP", "查询某个地址能否访问本机"),
        (7, "高级设置", "映射端口保护 %s · 检测与刷新周期" % ("开" if cfg["protect_dnat"] else "关")),
        (8, "维护与日志", "状态 · 日志 · 省份包 · 回滚"),
        (9, "更新与卸载", "当前版本 v" + APP_VERSION),
    ]))
    footer(("0", "退出"))
    notice(message)


def whitelist_menu():
    message = ""
    keys = {"1": "ips", "2": "cidrs", "3": "provinces"}
    notes = {"ips": "单个 IPv4 地址", "cidrs": "CIDR 网段，如 /24", "provinces": "按省份放行 IPv4"}
    while True:
        cfg = load_config()
        heading("白名单", "三类名单取并集：来源命中任意一项启用中的条目即可放行。")
        rows = []
        for number, key in keys.items():
            paused = len(cfg["paused"].get(key, ()))
            rows.append((number, LIST_TITLES[key], notes[key] + (" · 暂停 %d" % paused if paused else ""),
                         count_text(len(cfg[key]))))
        card("名单类型", option_lines(rows))
        footer(("0", "返回主菜单"))
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
    # IPv6 登录不经过本程序，名单变化不会断开它。
    if not source or is_ipv6(source) or not candidate["enabled"]:
        return True
    covered = source not in candidate["blocked_ips"] and bool(matching_sources(candidate, source))
    if not covered:
        return confirm("当前登录 IP %s 将失去权限，SSH 可能立即断开。继续？" % source)
    return True


def save_from_menu(original, candidate, done=""):
    candidate = validate_config(candidate)
    if candidate == original:
        return "没有变更，无需保存。"
    if not guard_session(candidate):
        return "已取消，配置未修改。"
    print("\n  " + style("正在保存并应用，请稍候…", "dim"), flush=True)
    edit_config(original, candidate)
    tail = ("：" + done + "。") if done else "。"
    return ("已保存并生效" + tail) if candidate["enabled"] else ("已保存（防护暂停中，开启后生效）" + tail)


def split_values(text):
    return [x for x in re.split(r"[,，、;；\s]+", text.strip()) if x]


def entry_rows(items, notes, offset=0, paused=(), numbers=None):
    paused = set(paused)
    numbers = numbers or [offset + index + 1 for index in range(len(items))]
    return [(number, item, entry_state(item, paused), notes.get(item, style("—", "dim")))
            for number, item in zip(numbers, items)]


def list_page(title, items, page=0, tip="", notes=None, paused=()):
    """分页表格；notes 不为 None 时显示状态和备注列。编号跨页保持一致。"""
    pages = max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)
    heading(title, *([tip] if tip else []))
    shown = items[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    if notes is not None:
        table(entry_rows(shown, notes, page * PAGE_SIZE, paused) or
              [("—", style("暂无条目", "dim"), "—", "—")], headers=("编号", "条目", "状态", "备注"))
    else:
        table([(page * PAGE_SIZE + index + 1, item) for index, item in enumerate(shown)] or
              [("—", style("暂无条目", "dim"))], headers=("编号", "条目"))
    navigation = [("", "共 %d 项 · 第 %d / %d 页" % (len(items), page + 1, pages))]
    if page + 1 < pages:
        navigation.append(("n", "下一页"))
    if page:
        navigation.append(("p", "上一页"))
    navigation.append(("0", "返回"))
    print()
    footer(*navigation)
    return pages


def next_page(value, page, pages):
    if value.lower() == "n":
        return min(page + 1, pages - 1)
    if value.lower() == "p":
        return max(page - 1, 0)
    return None


def province_grid(selected=(), paused=()):
    """全部省份一屏显示，按列编号；✔ 已添加（启用），停 已暂停。"""
    columns = 4 if box_inner() >= 54 else 3
    rows = (len(PROVINCE_NAMES) + columns - 1) // columns
    lines = []
    for row in range(rows):
        cells = []
        for column in range(columns):
            index = column * rows + row
            if index >= len(PROVINCE_NAMES):
                break
            name = PROVINCE_NAMES[index]
            mark = (style("停", "red") if name in paused else style("✔ ", "green") if name in selected
                    else "  ")
            cells.append(key_text("%2d" % (index + 1)) + " " + pad(name, 6) + " " + mark)
        lines.append("  ".join(cells))
    return lines


def province_input(selected=(), paused=()):
    message = ""
    while True:
        heading("白名单 / 省份白名单 / 添加",
                "输入编号或名称，可多个，例如：1 2 或 北京,广东。", "✔ 已添加并启用 · 停 已添加但暂停。")
        card("全部省份 · 已添加 %d 个" % len(selected), province_grid(selected, paused))
        footer(("0", "取消"))
        notice(message)
        value = read_choice("添加省份：")
        if value in ("0", ""):
            return "0"
        values = split_values(value)
        names = [PROVINCE_NAMES[int(x) - 1] if x.isdigit() and 1 <= int(x) <= len(PROVINCE_NAMES) else x
                 for x in values]
        if not all(resolve_province_code(x) for x in names):
            message = "未识别省份，请输入有效编号或名称。"
            continue
        return " ".join(names)


def list_path(key):
    """面包屑：白名单三类归于“白名单”之下。"""
    if key in WHITELIST_KEYS:
        return "白名单 / " + LIST_TITLES[key]
    return LIST_TITLES[key]


def select_entries(key, items, notes=None, paused=(), message=""):
    """管理条目列表：分页显示全部条目，输入编号（可多个或范围）选中。

    返回按列表顺序排列的所选条目；输入 0 或直接回车返回空列表。
    """
    page = 0
    while True:
        page = min(page, max(0, (len(items) - 1) // PAGE_SIZE))
        pages = list_page(list_path(key) + " / 管理条目", items, page,
                          "输入编号选中条目，可多个或范围，例如：1 3 或 2-5。", notes=notes, paused=paused)
        notice(message)
        value = read_choice("选择编号：")
        target = next_page(value, page, pages)
        if target is not None:
            page = target
            message = ""
            continue
        if value in ("0", ""):
            return []
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
            return [item for index, item in enumerate(items) if index in indices]
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


def input_notes(candidate, key, items, editing=False):
    notes = candidate["notes"].setdefault(key, {})
    heading(list_path(key) + (" / 修改备注" if editing else " / 填写备注"),
            "回车保留原备注，输入 - 清空，0 取消。" if editing else "备注可留空直接回车；输入 0 取消本次添加。",
            "备注最多 120 个字符。")
    for index, item in enumerate(items, 1):
        lines = [field_text("条目", style(item, "bold"))]
        if editing:
            lines.append(field_text("当前备注", notes.get(item, style("—", "dim"))))
        card("第 %d / %d 项" % (index, len(items)), lines)
        while True:
            prompt = "备注 [回车保留，- 清空，0 取消]：" if editing else "备注 [可留空，0 取消添加]："
            value = read_choice(prompt)
            if value == "0":
                return False
            try:
                value = validate_note(value)
            except AppError as exc:
                print("  " + style("✖ " + str(exc), "red"))
                continue
            if editing and value == "-":
                notes.pop(item, None)
            elif value:
                notes[item] = value
            break
    return True


def selected_rows(cfg, key, selected):
    """所选条目沿用管理列表中的编号，便于核对。"""
    items = cfg[key]
    return entry_rows(selected, cfg["notes"].get(key, {}), paused=cfg["paused"].get(key, ()),
                      numbers=[items.index(item) + 1 for item in selected])


def add_entries(key, cfg):
    path = list_path(key)
    items = cfg[key]
    candidate = copy.deepcopy(cfg)
    if key == "provinces":
        raw = province_input(items, paused=set(cfg["paused"].get(key, ())))
    else:
        example, prompt = LIST_EXAMPLES[key]
        heading(path + " / 添加", LIST_HINTS[key])
        card("输入示例", [example, style("多个用空格或逗号分隔；输入 0 取消。", "dim")])
        raw = read_choice(prompt)
    if raw in ("0", ""):
        return "已取消添加。"
    values = split_values(raw)
    if key != "provinces":
        # 先逐个校验：IPv6 或无效地址直接报错，而不是被当作旧版残留悄悄丢弃。
        addresses = [norm(x) for x in values]
    candidate[key].extend(values)
    if key == "ips":
        blocked = set(addresses) & set(cfg["blocked_ips"])
        if blocked:
            if not confirm("以下 IP 当前被禁止，将同时解除禁止：" + "、".join(sorted(blocked))):
                return "已取消添加。"
            candidate["blocked_ips"] = [x for x in cfg["blocked_ips"] if x not in blocked]
    candidate = validate_config(candidate)
    added = [item for item in candidate[key] if item not in items]
    if key in NOTE_KEYS and added and not input_notes(candidate, key, added):
        return "已取消添加。"
    return save_from_menu(cfg, candidate)


def remove_entries(key, cfg, selected):
    action = "解除禁止" if key == "blocked_ips" else "移除"
    candidate = copy.deepcopy(cfg)
    candidate[key] = [x for x in cfg[key] if x not in selected]
    heading(list_path(key) + " / 确认" + action)
    if key in NOTE_KEYS:
        table(selected_rows(cfg, key, selected), headers=("编号", "条目", "状态", "备注"))
    else:
        card("已选择 %d 项" % len(selected), ["• " + item for item in selected])
    if key == "ips":
        overlaps = []
        for address in selected:
            reasons = matching_sources(candidate, address)
            if reasons:
                overlaps.append(style(address, "bold"))
                overlaps += ["  · " + reason for reason in reasons]
        if overlaps:
            card("以下地址仍被其他名单放行", overlaps)
            card("移除方式", option_lines([
                (1, "彻底撤销访问权限", "移除重复的单 IP 直通地址，并加入禁止列表。"),
                (2, "只移除此处条目", "保留其他名单对它的放行。"),
            ], below=True))
            footer(("0", "取消"))
            mode = read_choice("请选择移除方式：")
            if mode == "1":
                candidate = revoke_addresses(candidate, selected)
            elif mode != "2":
                return "已取消移除。"
    if key == "blocked_ips":
        hint("解除禁止后，仍按白名单决定能否访问。")
    if not confirm("确认%s以上 %d 项？" % (action, len(selected))):
        return "已取消%s。" % action
    return save_from_menu(cfg, candidate)


def edit_notes(key, cfg, selected):
    candidate = copy.deepcopy(cfg)
    if not input_notes(candidate, key, selected, editing=True):
        return "已取消修改备注。"
    return save_from_menu(cfg, candidate)


def set_paused(key, cfg, selected, pausing):
    action = "暂停" if pausing else "启用"
    paused = set(cfg["paused"].get(key, ()))
    changed = [item for item in selected if (item not in paused) == pausing]
    if not changed:
        return "所选条目已经处于%s状态。" % action
    heading(list_path(key) + " / " + action + "条目",
            "暂停后保留条目和备注，但不再使用该条目放行。" if pausing else
            "启用后重新使用该条目放行；禁止列表仍然优先。")
    table(selected_rows(cfg, key, changed), headers=("编号", "条目", "状态", "备注"))
    if pausing:
        hint("其他已启用白名单、直通 IP 及访问设置仍可能放行该地址。")
    if not confirm("确认%s以上 %d 项？" % (action, len(changed))):
        return "已取消%s。" % action
    candidate = copy.deepcopy(cfg)
    new_paused = paused | set(changed) if pausing else paused - set(changed)
    candidate["paused"][key] = [item for item in cfg[key] if item in new_paused]
    return save_from_menu(cfg, candidate)


def entry_action(key, cfg, selected):
    """对所选条目执行一项操作；禁止 IP、直通 IP 只有“解除禁止 / 移除”，直接进入确认。"""
    if key not in NOTE_KEYS:
        return remove_entries(key, cfg, selected)
    message = ""
    while True:
        heading(list_path(key) + " / 已选择 %d 项" % len(selected))
        table(selected_rows(cfg, key, selected), headers=("编号", "条目", "状态", "备注"))
        print()
        card("操作", option_lines([
            (1, "修改备注", "补充、修改或清空备注"),
            (2, "暂停", "保留条目和备注，暂不放行"),
            (3, "启用", "恢复已暂停的条目"),
            (4, "移除", "从名单中删除，备注一并清除"),
        ]))
        footer(("0", "返回列表"))
        notice(message)
        choice = read_choice("请选择操作：")
        if choice in ("0", ""):
            return ""
        if choice == "1":
            return edit_notes(key, cfg, selected)
        if choice in ("2", "3"):
            return set_paused(key, cfg, selected, choice == "2")
        if choice == "4":
            return remove_entries(key, cfg, selected)
        message = "请输入 0 到 4 之间的编号。"


def manage_entries(key):
    """查看全部条目；选中后执行操作，完成后回到列表，可继续选择下一批。"""
    message = ""
    while True:
        cfg = load_config()
        items = cfg[key]
        if not items:
            return message or "列表为空，请先添加条目。"
        notes = cfg["notes"].get(key, {}) if key in NOTE_KEYS else None
        selected = select_entries(key, items, notes=notes, paused=cfg["paused"].get(key, ()), message=message)
        if not selected:
            return ""
        try:
            message = entry_action(key, cfg, selected)
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)


def edit_list(key):
    message = ""
    path = list_path(key)
    if key in NOTE_KEYS:
        add_note = "从省份表中选择，可填写备注" if key == "provinces" else "可批量；添加后可逐条填写备注"
        manage_note = "查看全部；选中后可改备注、暂停 / 启用或移除"
    else:
        add_note = "可批量，空格或逗号分隔"
        manage_note = "查看全部；选中后可" + ("解除禁止" if key == "blocked_ips" else "移除")
    while True:
        cfg = load_config()
        paused = cfg["paused"].get(key, ())
        heading(path, LIST_HINTS[key])
        summary = "当前条目 · %d 项" % len(cfg[key]) + (" · 暂停 %d" % len(paused) if paused else "")
        card(summary, entry_lines(cfg, key, limit=5, empty="暂无条目，选择“添加”开始设置。"))
        card("操作", option_lines([(1, "添加", add_note), (2, "管理条目", manage_note)]))
        footer(("0", "返回白名单" if key in WHITELIST_KEYS else "返回主菜单"))
        notice(message)
        choice = read_choice("请选择：")
        message = ""
        if choice == "0":
            return
        if choice == "":
            continue
        try:
            if choice == "1":
                message = add_entries(key, cfg)
            elif choice == "2":
                message = manage_entries(key)
            else:
                message = "请输入 0 到 2 之间的编号。"
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)


def address_report(address):
    """返回 [(卡片标题, 行)]；依据上次成功生效的规则，而非磁盘上更新的省份缓存。"""
    with operation_lock():
        current = read_state().get("current")
        if not current:
            raise AppError("暂无成功应用记录")
        cfg = validate_config(current["config"])  # 旧版记录换算为当前格式
        if is_ipv6(address):
            return [("检查结果 · " + address,
                     [field_text("过滤状态", style("IPv6 不经过本程序", "bold") +
                                 style("  不放行也不拦截，由其他防火墙或云安全组决定", "dim"))])]
        if not live_table():
            return [("检查结果 · " + address,
                     [field_text("过滤状态", style("○ 本程序过滤未启用", "red") +
                                 style("  入站不受本程序限制", "dim"))])]
        if address in cfg["blocked_ips"]:
            return [("检查结果 · " + address,
                     [field_text("业务入站", style("✖ 禁止访问", "red") + style("  命中禁止列表", "dim"))])]
        match = re.search(r"set allow4 \{(.*?)\n    \}", current["rules"], re.S)
        elements = re.search(r"elements = \{ (.*?) \}", match.group(1)) if match else None
        networks = elements.group(1).split(", ") if elements else []
        permitted = any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in networks)
        mode = cfg["ping_mode"]
        pingable = mode == "all" or (mode == "whitelist" and permitted)
        ping_note = {"off": "  已设置全部禁止 ping",
                     "whitelist": "  仅白名单可 ping",
                     "all": "  ping 通不代表业务端口可访问"}[mode]
        lines = [field_text("业务入站", style("✔ 允许访问", "green") if permitted else
                            style("✖ 拒绝访问", "red") + style("  包括既有入站连接", "dim")),
                 field_text("公网 Ping", (style("✔ 可以 ping", "green") if pingable else
                                          style("✖ 不能 ping", "red")) + style(ping_note, "dim"))]
        reasons = ["• " + reason for reason in matching_sources(cfg, address)]
    return [("检查结果 · " + address, lines),
            ("覆盖线索", (reasons or [style("没有启用中的名单覆盖该地址。", "dim")]) +
             [style("来自配置和当前缓存，已暂停条目不计入；实际判定以上次生效规则为准。", "dim")])]


def check_address():
    report, message = [], ""
    while True:
        heading("检查 IP", "依据上次成功生效的规则判断；其他防火墙或云安全组需另行检查。")
        for title, lines in report:
            card(title, lines)
        footer(("0", "返回主菜单"))
        notice(message)
        raw = read_choice("输入要检查的 IP：")
        if raw in ("0", ""):
            return
        report, message = [], ""
        try:
            report = address_report(str(ipaddress.ip_address(raw)))
        except ValueError:
            message = "操作未完成：无效 IP 地址：" + raw
        except (AppError, OSError) as exc:
            message = "操作未完成：" + str(exc)


def options_menu():
    message = ""
    keys = {"1": "protect_dnat"}
    while True:
        cfg = load_config()
        heading("高级设置", "选择编号即可切换，修改后立即保存生效。")
        card("访问规则", option_lines([(number, OPTION_TEXT[key][0], OPTION_TEXT[key][1],
                                        option_badge(key, cfg[key])) for number, key in keys.items()],
                                      below=True))
        refresh = cfg["province_refresh"]
        card("其他参数", [
            field_text("配置检测", "每 %d 秒" % cfg["watch_interval"]),
            field_text("省份刷新", ("每 %g 小时" % (refresh / 3600)) if refresh else "仅手动刷新"),
            style("以上参数请编辑配置文件，保存后自动生效：", "dim"),
            style(CONFIG_PATH, "dim"),
        ])
        footer(("0", "返回主菜单"))
        notice(message)
        choice = read_choice("请选择：")
        message = ""
        if choice == "0":
            return
        if not choice:
            continue
        key = keys.get(choice)
        if not key:
            message = "请输入菜单中的编号。"
            continue
        try:
            candidate = copy.deepcopy(cfg)
            candidate[key] = not cfg[key]
            if key == "protect_dnat" and not candidate[key] and not confirm("映射端口将不再受本程序保护。继续？"):
                message = "已取消，设置未修改。"
                continue
            message = save_from_menu(cfg, candidate, "%s %s" % (OPTION_TEXT[key][0],
                                                                 "已开启" if candidate[key] else "已关闭"))
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)


def local_province_packages():
    packages = []
    for name in PROVINCE_NAMES:
        path = Path(CACHE_DIR) / (resolve_province_code(name) + ".txt")
        if not path.is_file():
            continue
        package = {"name": name, "networks": None, "updated_at": None, "error": ""}
        try:
            # Read metadata and contents from the same file even if a refresh replaces its path.
            with path.open("rb") as stream:
                package["updated_at"] = os.fstat(stream.fileno()).st_mtime
                data = stream.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise AppError("缓存过大")
            package["networks"] = len(parse_province(data.decode("utf-8")))
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError, AppError):
            package["error"] = "缓存无效或无法读取"
        packages.append(package)
    return packages


def view_local_province_packages():
    page = 0
    while True:
        packages = local_province_packages()
        cfg = load_config()
        selected = set(cfg["provinces"])
        paused = set(cfg["paused"].get("provinces", ()))
        pages = max(1, (len(packages) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = min(page, pages - 1)
        heading("维护与日志 / 本地省份包", "只读页面：显示已下载的省份缓存，不会触发下载或修改规则。",
                "“使用”对应省份白名单设置；未选用的缓存不参与放行。")
        rows = []
        for index in range(page * PAGE_SIZE, min((page + 1) * PAGE_SIZE, len(packages))):
            package = packages[index]
            name = package["name"]
            usage = (style("暂停", "red") if name in paused else style("启用", "green") if name in selected
                     else style("未选用", "dim"))
            updated = (time.strftime("%Y.%m.%d %H:%M", time.localtime(package["updated_at"]))
                       if package["updated_at"] is not None else "更新时间未知")
            detail = style(package["error"], "red") if package["error"] else "%d 个网段" % package["networks"]
            rows.append((index + 1, name, usage, detail + "\n" + style(updated, "dim")))
        table(rows or [("—", style("暂无本地省份包", "dim"), "—", "添加省份后自动下载")],
              headers=("编号", "省份", "使用", "本地数据"))
        navigation = [("", "本地共 %d 个省份包 · 第 %d / %d 页" % (len(packages), page + 1, pages))]
        if page + 1 < pages:
            navigation.append(("n", "下一页"))
        if page:
            navigation.append(("p", "上一页"))
        navigation.append(("0", "返回"))
        print()
        footer(*navigation)
        value = read_choice("请选择：")
        if value in ("0", ""):
            return
        target = next_page(value, page, pages)
        if target is not None:
            page = target


def backup_summary():
    try:
        previous = read_state().get("previous")
    except AppError:
        return style("状态不可读", "red")
    if not previous:
        return style("暂无备份", "dim")
    timestamp = previous.get("applied_at")
    return style("备份于 " + time.strftime("%m-%d %H:%M", time.localtime(timestamp)) if timestamp else "有备份", "dim")


def maintenance_menu():
    message = ""
    while True:
        heading("维护与日志")
        card("查看", option_lines([(1, "运行状态", "防护、服务、同步情况和全部名单"),
                                   (2, "最近日志", "后台服务最近 40 行日志"),
                                   (3, "本地省份包", "已下载的省份缓存和更新时间")]))
        card("操作", option_lines([(4, "刷新省份数据", "重新下载启用中的省份并应用"),
                                   (5, "恢复上一版", "还原上次成功的配置和访问权限", backup_summary())]))
        footer(("0", "返回主菜单"))
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
                heading("维护与日志 / 最近日志")
                result = run(["journalctl", "-u", "vps-firewall", "-n", "40", "--no-pager"])
                print(result.stdout or result.stderr)
                pause()
            elif choice == "3":
                view_local_province_packages()
            elif choice == "4":
                heading("维护与日志 / 刷新省份数据")
                print("  " + style("正在刷新省份数据，请稍候…", "dim"), flush=True)
                apply_once(force_refresh=True)
                notice("刷新流程已完成。下载失败时会使用旧缓存，详情见上方输出。")
                pause()
            elif choice == "5":
                previous = read_state().get("previous")
                if not previous:
                    message = "暂无上一版配置。成功修改配置后即可使用。"
                    continue
                heading("维护与日志 / 恢复上一版", "将同时恢复当时的配置和访问权限。")
                timestamp = previous.get("applied_at")
                if timestamp:
                    card("上一版备份", [field_text("备份时间", time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(timestamp)))])
                if guard_session(previous["config"]) and confirm("确认恢复？"):
                    rollback()
                    message = "已恢复上一版配置和规则。"
                else:
                    message = "已取消恢复。"
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
    if action == "更新程序":
        heading("更新与卸载 / 更新程序", "当前版本：v" + APP_VERSION,
                "将检查并安装最新正式版本，保留现有配置和数据；完成后自动重新打开菜单。")
        if not confirm("确认更新程序？"):
            return None
        result = update_program()
        if result == 0:
            # Replace this process so the menu uses the newly installed code and version.
            os.execv(sys.executable, [sys.executable, "/opt/vps-firewall/vps_firewall.py", "menu"])
    else:
        heading("更新与卸载 / 卸载程序", "将停止防护，删除本程序的规则、服务和安装文件。",
                "配置、缓存和历史会先备份，备份位置将在卸载后显示。")
        if not confirm("确认卸载程序？"):
            return None
        result = subprocess.call(["bash", str(Path(__file__).with_name("uninstall.sh")), "--yes"])
    if result != 0:
        print("\n  " + style("✖ %s未完成，请检查上方错误信息。菜单已退出。" % action, "red"))
    return result


def program_page():
    """返回 None 表示回到主菜单；返回整数表示菜单应以该退出码结束。"""
    message = ""
    actions = {"1": "更新程序", "2": "卸载程序"}
    while True:
        heading("更新与卸载")
        card("当前版本", [field_text("程序版本", "vps-firewall v" + APP_VERSION),
                          field_text("发布日期", APP_RELEASE_DATE),
                          field_text("安装位置", "/opt/vps-firewall")])
        card("操作", option_lines([
            (1, "更新程序", "安装最新正式版，保留配置和数据，完成后自动重开菜单"),
            (2, "卸载程序", "删除本程序的规则、服务和文件；配置、缓存和历史先备份"),
        ], below=True))
        footer(("0", "返回主菜单"))
        notice(message)
        choice = read_choice("请选择：")
        message = ""
        if choice == "0":
            return None
        if not choice:
            continue
        action = actions.get(choice)
        if not action:
            message = "请输入 0 到 2 之间的编号。"
            continue
        try:
            result = program_menu(action)
        except OSError as exc:
            print("\n  " + style("✖ %s未完成：%s。菜单已退出。" % (action, exc), "red"))
            return 1
        if result is not None:
            return result
        message = "已取消%s。" % action


def toggle_protection(cfg, active):
    if cfg["enabled"] != active:
        action = protection_action(cfg, active)
        heading(action, "将按保存的开关重新应用规则，不改变保存的设置。")
        if confirm("确认%s？" % action) and guard_session(cfg):
            edit_config(cfg, cfg)
            return "已按保存的开关重新应用规则。"
        return "已取消，配置未修改。"
    pausing = cfg["enabled"]
    candidate = copy.deepcopy(cfg)
    candidate["enabled"] = not pausing
    heading("暂停防护" if pausing else "开启防护",
            "暂停后，本程序将不再拦截入站访问；状态会保存，重启后保持。" if pausing else
            "开启后，按当前白名单和禁止列表限制入站访问。")
    if not confirm("确认%s？" % ("暂停防护" if pausing else "开启防护")):
        return "已取消，防护状态未改变。"
    result = save_from_menu(cfg, candidate)
    if not result.startswith("已保存"):
        return result
    return "已保存：防护已暂停，本程序不再拦截入站访问。" if pausing else "已保存并生效：防护已开启。"


def interactive_menu():
    message = ""
    while True:
        try:
            try:
                cfg = load_config()
            except (AppError, OSError, ValueError) as exc:
                heading("配置需要恢复")
                card("配置无法读取", [style(str(exc), "red")])
                current = read_state().get("current")
                if not current or not confirm("是否恢复最近一次成功配置？"):
                    return 1
                with operation_lock():
                    recover_pending()
                    current = read_state()["current"]
                    if not Path(CONFIG_PATH).exists():
                        atomic_write(CONFIG_PATH, dump_config(current["config"]))
                    commit(*record_policy(current), save=True)
                message = "已恢复最近一次成功配置。"
                continue
            with operation_lock():
                cfg = load_config()
                current = read_state().get("current")
                active = live_table()
            render_home(cfg, active, ssh_source(),
                        bool(current and current["config"] == cfg), message)
            choice = read_choice("请输入编号：")
            message = ""
            if choice == "0":
                print("\n  " + style("已退出，防护保持当前状态。", "dim"))
                return 0
            if choice == "":
                continue
            keys = {"2": "blocked_ips", "3": "rescue_ips"}
            if choice == "1":
                whitelist_menu()
            elif choice in keys:
                edit_list(keys[choice])
            elif choice == "4":
                message = toggle_protection(cfg, active)
            elif choice == "5":
                message = ping_menu()
            elif choice == "6":
                check_address()
            elif choice == "7":
                options_menu()
            elif choice == "8":
                maintenance_menu()
            elif choice == "9":
                result = program_page()
                if result is not None:
                    return result
            else:
                message = "请输入 0 到 9 之间的编号。"
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)
            # Avoid an immediate redraw loop if reading configuration/firewall itself failed.
            notice(message)
            if read_choice("回车重试，0 退出：") == "0":
                return 1


def ping_menu():
    """公网 Ping 三档选择；选中后立即保存生效并返回主菜单，结果显示在主菜单。"""
    modes = {"1": "off", "2": "whitelist", "3": "all"}
    message = ""
    while True:
        cfg = load_config()
        heading("公网 Ping", "只影响 ping（ICMP echo-request），不影响业务端口；禁止 IP 始终不能 ping。")
        card("Ping 模式", option_lines([
            (number, PING_TEXT[mode][0], PING_TEXT[mode][1],
             style("● 当前", "green") if cfg["ping_mode"] == mode else "")
            for number, mode in modes.items()], below=True))
        footer(("0", "返回主菜单"))
        notice(message)
        choice = read_choice("请选择：")
        if choice in ("0", ""):
            return ""
        mode = modes.get(choice)
        if not mode:
            message = "请输入 0 到 3 之间的编号。"
            continue
        candidate = copy.deepcopy(cfg)
        candidate["ping_mode"] = mode
        try:
            return save_from_menu(cfg, candidate, ping_summary(mode))
        except (AppError, OSError, ValueError) as exc:
            message = "操作未完成：" + str(exc)


def ping_command(value=None):
    """命令行：vps-firewall ping [off|whitelist|all]；on 等同 all；不带参数时只显示当前状态。"""
    cfg = load_config()
    if value is not None:
        candidate = copy.deepcopy(cfg)
        candidate["ping_mode"] = PING_ALIASES[value]
        if candidate != cfg:
            edit_config(cfg, candidate)
        cfg = candidate
    print(ping_summary(cfg["ping_mode"]) + ("" if cfg["enabled"] else "（防护暂停中，开启后生效）"))


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
        if source and is_ipv6(source):
            log("当前通过 IPv6 登录（%s）；本程序只过滤 IPv4，该地址不会加入管理地址" % source)
        elif source and source not in addresses:
            addresses.append(source)
        if not addresses and sys.stdin.isatty():
            addresses = split_values(read_choice("请输入管理/抢救 IP（IPv4，多个用空格分隔）："))
        if not addresses:
            raise AppError("无法确定 IPv4 管理 IP；请执行 sudo bash install.sh 你的管理IP")
        addresses = [norm(x) for x in addresses]  # 明确填写的 IPv6 直接报错
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
                                 "version", "update", "ping"])
    parser.add_argument("value", nargs="?", choices=list(PING_ALIASES),
                        help="仅用于 ping：off 全部禁止 / whitelist 仅白名单 / all 所有人（on 等同 all）；省略则显示当前状态")
    parser.add_argument("--force", action="store_true", help="强制刷新省份数据")
    parser.add_argument("--rescue", default="", help="首次安装的管理 IP，多个用逗号分隔")
    parser.add_argument("--tag", help="update 指定正式版本，例如 v1.0.0")
    args = parser.parse_args()
    if args.tag and args.command != "update":
        parser.error("--tag 仅用于 update")
    if args.value and args.command != "ping":
        parser.error("off / whitelist / all 只能用于 ping 命令")
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
        elif args.command == "ping":
            ping_command(args.value)
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
