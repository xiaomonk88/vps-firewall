# 更新记录

## 1.3.0（2026.09.30）

- **去掉全部 IPv6 功能，只过滤 IPv4。** 规则表由 `inet vps_wl` 改为 `ip vps_wl`，IPv6 流量不经过本程序，既不放行也不拦截。VPS 有公网 IPv6 且没有其他防火墙或云安全组时，所有端口都可通过 IPv6 访问。
- 删除“IPv6 全部放行”开关（`allow_all_ipv6`），高级设置只保留映射端口保护。
- 白名单、网段、禁止 IP、直通 IP 只接受 IPv4；输入 IPv6 直接报错。
- 升级：旧 `inet vps_wl` 表在第一次应用时于同一事务中删除；旧配置中的 IPv6 条目、备注、暂停状态和 `allow_all_ipv6` 自动忽略，应用时从配置文件中清除并在日志列出。原来禁止的 IPv6 地址不再被拦截。直通 IP 只有 IPv6 时升级前校验失败，旧版本保持运行。
- 开机恢复、回滚和后台检测遇到旧版规则记录时按配置重新生成，不再原样恢复旧 inet 规则。
- 通过 IPv6 登录时，首次安装不再把该地址存为直通 IP，修改名单也不再提示可能断开当前 SSH；“检查 IP”对 IPv6 地址说明其不经过本程序。
- 公网 Ping 三档只作用于 IPv4。
- 卸载时同时删除新旧两种规则表。

- 公网 Ping 改为三档：`全部禁止`（任何来源都不可 ping，包括白名单和直通 IP）、`仅白名单`（默认）、`所有人`。主菜单 `5` 进入选择页，选中即保存生效；命令为 `vps-firewall ping off|whitelist|all`，`on` 等同 `all`。
- 配置项 `allow_ping` 改为 `ping_mode = "off" / "whitelist" / "all"`。旧配置自动换算：`true` → `all`，`false` → `whitelist`，升级后 ping 行为不变。**注意：`ping off` 的含义变了**，旧版表示“仅白名单可 ping”，现在表示全部禁止；脚本里用到 `ping off` 的请改为 `ping whitelist`。
- “检查 IP”按档位判断该地址能否 ping；“运行状态”显示当前档位。
- 省份数据下载的 User-Agent 改为实际版本号。
- 卸载提示写明备份目录 `/var/lib/vps-firewall-uninstalled.XXXXXX/`。
