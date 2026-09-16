#!/usr/bin/env python3
"""Install a published GitHub release, or update the installed release."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

DEFAULT_REPO = "xiaomonk88/vps-firewall"
INSTALL_DIR = Path("/opt/vps-firewall")
SOURCE_PATH = INSTALL_DIR / "source.json"
LOCK_PATH = Path("/run/lock/vps-firewall-update.lock")
FILES = ("install.sh", "uninstall.sh", "vps_firewall.py",
         "vps-firewall.service", "github_install.py", "VERSION")
MAX_DOWNLOAD = 20 * 1024 * 1024


def validate_repo(repo):
    if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repo):
        raise ValueError("仓库格式应为 用户名/仓库名")
    return repo


def validate_tag(tag):
    if not isinstance(tag, str) or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("版本格式应为 v1.0.0，只支持正式版本")
    return tag


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "vps-firewall-installer"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("下载内容超过大小限制")
    return data


def unpack_release(data, destination, tag):
    # Only copy the known installation files. Never extract arbitrary archive paths.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        roots = {name.split("/")[0] for name in archive.namelist() if "/" in name}
        if len(roots) != 1:
            raise ValueError("发布包目录结构无效")
        root = roots.pop()
        payloads = {}
        for filename in FILES:
            name = root + "/" + filename
            if archive.namelist().count(name) != 1:
                raise ValueError("发布包缺少文件或包含重复文件：" + filename)
            if archive.getinfo(name).file_size > 2 * 1024 * 1024:
                raise ValueError("发布文件过大：" + filename)
            payloads[filename] = archive.read(name)
        version = payloads["VERSION"].decode("utf-8").strip()
        if "v" + version != tag:
            raise ValueError("发布标签与 VERSION 不一致，已取消安装")
        for filename, content in payloads.items():
            (destination / filename).write_bytes(content)


def backup_installation():
    if not INSTALL_DIR.exists():
        return
    backup_root = Path("/var/backups/vps-firewall")
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = Path(tempfile.mkdtemp(prefix="before-update-", dir=backup_root))
    shutil.copytree(INSTALL_DIR, backup / "program")
    config_dir = Path("/etc/vps-firewall")
    if config_dir.exists():
        shutil.copytree(config_dir, backup / "config")
    print("更新前程序和配置已备份到：" + str(backup), flush=True)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="从 GitHub 正式发布版本安装或更新 vps-firewall")
    parser.add_argument("--repo", help="GitHub 用户名/仓库名")
    parser.add_argument("--tag", help="指定正式版本，如 v1.0.0；默认最新 Release")
    parser.add_argument("--rescue", default="", help="首次安装的管理 IP，多个用逗号分隔")
    args = parser.parse_args(argv)
    try:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise ValueError("请在 Debian 12/13 上使用 sudo python3 运行")
        import fcntl
        with open(LOCK_PATH, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            source = json.loads(SOURCE_PATH.read_text(encoding="utf-8")) if SOURCE_PATH.exists() else {}
            repo = validate_repo(args.repo or source.get("repo", DEFAULT_REPO))
            tag = args.tag
            if tag is None:
                release = json.loads(download("https://api.github.com/repos/" + repo + "/releases/latest"))
                tag = release["tag_name"]
            tag = validate_tag(tag)
            current = INSTALL_DIR / "VERSION"
            if (source.get("repo") == repo and source.get("tag") == tag
                    and current.exists() and current.read_text().strip() == tag[1:]):
                print("已是目标版本：" + tag)
                return 0
            print("正在下载 %s %s…" % (repo, tag), flush=True)
            data = download("https://codeload.github.com/" + repo + "/zip/refs/tags/" + tag)
            with tempfile.TemporaryDirectory(prefix="vps-firewall-") as temporary:
                directory = Path(temporary)
                unpack_release(data, directory, tag)
                subprocess.run([sys.executable, str(directory / "vps_firewall.py"), "--help"],
                               check=True, stdout=subprocess.DEVNULL)
                subprocess.run(["bash", "-n", str(directory / "install.sh"),
                                str(directory / "uninstall.sh")], check=True)
                backup_installation()
                subprocess.run(["bash", str(directory / "install.sh"), args.rescue], check=True)
            source_temp = SOURCE_PATH.with_suffix(".tmp")
            source_temp.write_text(json.dumps({"repo": repo, "tag": tag}) + "\n", encoding="utf-8")
            source_temp.replace(SOURCE_PATH)
            print("安装完成：%s；以后运行 sudo vps-firewall update 更新。" % tag)
            return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.CalledProcessError) as exc:
        print("安装/更新失败：%s" % exc, file=sys.stderr)
        print("若已进入安装阶段，请检查上方输出及 journalctl -u vps-firewall；程序备份位于 /var/backups/vps-firewall。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
