#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo '请使用 sudo bash uninstall.sh'; exit 1; }
echo '即将停止白名单并删除程序文件；配置、缓存和历史将保存在 /var/lib 中。'
if [ "${1:-}" != '--yes' ]; then
  read -r -p '输入 y 确认卸载：' answer || exit 1
  [[ "$answer" == y || "$answer" == Y ]] || { echo '已取消'; exit 0; }
fi
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
systemctl stop vps-firewall 2>/dev/null || true
# 先迁移/恢复旧版系统配置，再处理数据目录，避免删除备份后无法恢复。
python3 "$SCRIPT_DIR/vps_firewall.py" migrate
# 与菜单及手动应用串行。无法获取锁或清除规则时终止，不假报卸载成功。
exec 9>/run/lock/vps-firewall.lock
flock -x 9
backup_dir="$(mktemp -d /var/lib/vps-firewall-uninstalled.XXXXXX)"
if [ -d /etc/vps-firewall ]; then cp -a /etc/vps-firewall "$backup_dir/config"; fi
if [ -d /var/lib/vps-firewall ]; then cp -a /var/lib/vps-firewall "$backup_dir/data"; fi
printf 'add table inet vps_wl\ndelete table inet vps_wl\n' | nft -f -
systemctl disable vps-firewall >/dev/null 2>&1 || true
rm -f /etc/systemd/system/vps-firewall.service /usr/local/bin/vps-firewall
# 固定安装路径；不递归删除上传目录。
rm -rf -- /opt/vps-firewall /etc/vps-firewall /var/lib/vps-firewall
systemctl daemon-reload
echo "已卸载。配置、缓存和历史可从 $backup_dir 恢复。其他防火墙规则保留。"
