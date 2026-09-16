#!/usr/bin/env bash
set -euo pipefail

# Debian 12/13: sudo bash install.sh [管理IP，多个用逗号分隔]
[ "$(id -u)" -eq 0 ] || { echo '请使用 sudo bash install.sh'; exit 1; }
. /etc/os-release
[[ "$ID" == debian && "${VERSION_ID:-}" =~ ^(12|13)$ ]] || {
  echo '仅支持 Debian 12/13'; exit 1;
}
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
for name in vps_firewall.py vps-firewall.service uninstall.sh github_install.py VERSION; do
  [ -f "$SCRIPT_DIR/$name" ] || { echo "缺少文件：$name，请上传整个程序目录"; exit 1; }
done

echo '[1/5] 安装运行依赖...'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nftables python3 ca-certificates
python3 -c 'import sys; assert sys.version_info >= (3, 11), "需要 Python 3.11+"'

echo '[2/5] 校验程序，准备配置（重复安装保留配置）...'
python3 "$SCRIPT_DIR/vps_firewall.py" --help >/dev/null
mkdir -p /opt/vps-firewall /etc/vps-firewall /var/lib/vps-firewall
chmod 700 /etc/vps-firewall /var/lib/vps-firewall
# sudo 可能不保留 SSH_CONNECTION；这时要求显式输入，不猜测 SSH 端口。
python3 "$SCRIPT_DIR/vps_firewall.py" init --rescue "${1:-${RESCUE_IP:-}}"
# 更新前用新程序校验现有配置和规则；失败时旧程序继续运行。
python3 "$SCRIPT_DIR/vps_firewall.py" test

echo '[3/5] 更新程序文件...'
# 停止旧进程，防止旧版本继续覆盖规则；停止服务本身不会清除现有防火墙。
systemctl stop vps-firewall 2>/dev/null || true
safe_install() {
  if [ ! "$1" -ef "$2" ]; then install -m "$3" "$1" "$2"; fi
}
safe_install "$SCRIPT_DIR/vps_firewall.py" /opt/vps-firewall/vps_firewall.py 0755
safe_install "$SCRIPT_DIR/uninstall.sh" /opt/vps-firewall/uninstall.sh 0755
safe_install "$SCRIPT_DIR/github_install.py" /opt/vps-firewall/github_install.py 0755
safe_install "$SCRIPT_DIR/VERSION" /opt/vps-firewall/VERSION 0644
safe_install "$SCRIPT_DIR/vps-firewall.service" /etc/systemd/system/vps-firewall.service 0644
cat > /usr/local/bin/vps-firewall <<'EOF'
#!/usr/bin/env bash
export PYTHONUTF8=1
exec /usr/bin/python3 /opt/vps-firewall/vps_firewall.py "$@"
EOF
chmod 0755 /usr/local/bin/vps-firewall

echo '[4/5] 迁移旧版持久化文件并校验防火墙...'
python3 /opt/vps-firewall/vps_firewall.py migrate
python3 /opt/vps-firewall/vps_firewall.py test
python3 /opt/vps-firewall/vps_firewall.py apply

echo '[5/5] 应用规则并启用开机服务...'
systemctl daemon-reload
systemctl enable vps-firewall >/dev/null
# ExecStartPre 同步恢复已验证规则；恢复失败会使启动失败。
if ! systemctl restart vps-firewall; then
  echo '服务启动失败，现有规则未主动清除。请查看：journalctl -u vps-firewall -n 40 --no-pager'
  exit 1
fi
systemctl is-active --quiet vps-firewall
vps-firewall status
echo
echo '安装完成。打开中文管理菜单：sudo vps-firewall'
echo '也可以使用：sudo vps-firewall menu'
echo '卸载：sudo bash /opt/vps-firewall/uninstall.sh'
