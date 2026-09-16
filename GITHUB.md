# GitHub 开发和发布

仓库：https://github.com/xiaomonk88/vps-firewall

`main` 保存开发代码，正式 Release 供 VPS 安装。推送代码不会自动更新 VPS；服务器管理员执行 `sudo vps-firewall update` 时才更新。

## 第一次上传

在本项目目录打开 PowerShell。Git 首次上传时通过 Git Credential Manager 登录 GitHub；无需把密码或 Token 写进文件。

```powershell
git init -b main
git config user.name "xiaomonk88"
git config user.email "152084945+xiaomonk88@users.noreply.github.com"
git remote add origin https://github.com/xiaomonk88/vps-firewall.git
git add .
git diff --cached --stat
git commit -m "Prepare vps-firewall v1.0.0"
git push -u origin main
```

如果已经完成初始化和绑定仓库，直接从提交修改开始。`.gitignore` 排除了 Python 缓存、运行配置、日志和常见密钥文件；提交前仍应检查改动列表。

首次正式发布：

```powershell
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions 会执行测试和 Shell 语法检查，并验证标签与 `VERSION` 一致，通过后自动创建 Release。可在仓库的 Actions 和 Releases 页面查看。安装入口需要至少有一个成功发布的 Release。

## 以后开发好了如何上传

```powershell
python -m unittest discover -s tests -v
git add .
git diff --cached --stat
git commit -m "说明本次修改"
git push
```

准备让 VPS 使用新版本时，把 `VERSION` 改为新的版本号，例如 `1.0.1`，同时将 `vps_firewall.py` 中的 `APP_RELEASE_DATE` 更新为本版修改日期（如 `2026.09.16`），并补充 `CHANGELOG.md`，和代码一起提交、推送，然后：

```powershell
git tag v1.0.1
git push origin v1.0.1
```

每次发布使用新的标签，不覆盖已发布标签。若 Actions 失败，先修复问题；仅普通代码推送不会创建 Release。

## VPS 安装、更新

见 [README.md](README.md) 中的一键安装命令。更新命令：

```bash
vps-firewall version
sudo vps-firewall update
# 也可指定已发布的版本：
sudo vps-firewall update --tag v1.0.0
```

安装器仅下载 GitHub 正式版本，校验必需文件及 `VERSION` 后调用安装脚本。更新沿用 `/etc/vps-firewall/config.toml` 和 `/var/lib/vps-firewall/` 中的数据，程序和配置另备份到 `/var/backups/vps-firewall/before-update-*/`。安装来源保存在 `/opt/vps-firewall/source.json`。

下载或发布包校验失败时不会开始安装。进入安装阶段后，新程序会先校验现有配置与规则，再替换程序并重启服务。备份不等于自动恢复；若安装阶段失败，查看终端错误和 `sudo journalctl -u vps-firewall -n 40 --no-pager`，修复原因后重试，必要时使用备份恢复程序和配置。

`vps-firewall rollback` 仍表示恢复上一版防火墙配置和规则；它不回退程序版本。跨版本降级前应确认配置兼容性。

旧版本没有 `update` 命令时，重新运行 README 中的一键安装命令即可升级。从 1.0.8 起，安装器会识别运行 `/opt/vps-whitelist/whitelist.py` 的旧 `vps-whitelist` 服务并停止、禁用它，防止与新版覆盖同一规则表，旧文件仍保留。若运行中的同名服务无法识别，安装会中止并提示检查。旧目录的配置不会自动复制到新版；已有 `/etc/vps-firewall/` 配置继续保留。

本地 Windows 测试不代表已经验证真实 VPS 安装、重启及网络连接。GitHub 的默认测试也会跳过需要 root 的网络测试；可按程序功能说明在 Debian 上运行网络命名空间测试。
