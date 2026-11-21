# 浏览器指纹维护闭环

目标：让“发现版本”“采集候选”“校验通过”“已采用”有独立状态，避免把 Actions 成功或已有版本名称当作完成实测更新。

## 执行规划与已实现流程

1. `browser-maintenance.yml` 每日 UTC 02:17（北京时间 10:17）检查 Edge、Chrome、Firefox 普通稳定版，也可手动选择单个产品与完整版本。GitHub 定时运行可能延迟。
2. 各产品独立使用原只读 `browser-update.yml` 采集，不互相取消。固定一次发现的完整版本；Chrome/Edge 校验官方分发身份与签名，Firefox 校验官方 HTTPS SHA512。每产品采集 15 个全新冷连接，覆盖 TLS1.2/H1、TLS1.3/H1、TLS1.3/H2。
3. 在线和离线各回放三个场景。自动采用要求六次静态 TLS、导航头及 H2 初始观察字段全部匹配，包含 stream ID。未知扩展、不支持能力、签名/摘要错误、缺样、重复或差异均阻断。
4. 独立 Linux 写入任务重新核对同运行、同源码提交、精确版本/范围、原始事件摘要、三个场景/五样本、六个唯一回放、实际对比值、已回放 Spec 和 Bundle 字节。一次只允许修改一个产品版本的 Windows 配置，合并不同产品时保留旧观察历史及其它配置。
5. 组合目录执行 Go 单测、race、vet，导出完整离线 Bundle 及 SHA256 manifest。通过后在分支正常保护允许时，以非强制的 fast-forward 提交采用数据；不绕过保护。默认分支有新提交或写入失败时保留现有目录及证据，任务失败，不能报告已采用。
6. 采用提交记录在 `maintenance-result.json`，精确版本、Spec 摘要、采集来源、限制与运行链接进入 `maintenance-state.json`。DataRevision 根据目录内容生成；模块版本与数据修订分开。离线 manifest 区分采集源提交、采用提交和未提交的演练结果。

`adopt=false` 仅生成验证后的演练产物；旧的手动候选入口仍保持只读。没有自动安装浏览器、修改用户 ProfileStore、升级 SDK、创建模块标签或发布 npm/PyPI。已安装 SDK 的依赖仍固定，用户需要显式采用新 Bundle 或升级未来正式模块版本。

## 状态与故障

- `candidate`：采集与回放产物，尚未采用。
- `validated`：独立采用门禁通过，仍须检查采用提交是否已写入远端。
- `adopted=true` 与 `adopted_commit`：已核验远端提交的回执。
- `no_change`：完整构建、三个传输和全部必需回放字段已经验证，不是按主版本或 UA 判断。
- `blocked`：失败或缺少报告；不会覆盖有效配置。其它产品成功的候选仍可采用，整体运行保持失败。

Actions 的失败通知沿用 GitHub 仓库通知；可在运行摘要查看产品状态，下载 `browser-profile-candidate-<product>` 原始证据以及 `browser-maintenance-result` 的完整快照、manifest 和采用回执。原始证据及结果保留 90 天；长期归档应另存。重复执行会先核对精确版本，成功采用后无需重复采集。

组织当前禁止 Actions 创建或批准 PR，首次配置请求被拒绝，保持原设置。默认工作流权限仍为只读，只有采用任务取得 `contents: write`，使用 GITHUB_TOKEN 正常提交；若分支保护要求人工审查或禁止直接写入，明确失败，不放宽保护。GITHUB_TOKEN 写入不会触发普通 push CI，因此采用任务自身完成组合测试。

## 测试策略和边界

流程/工具改动首先检查选择、失败拦截、只读与采用边界；实际 TLS 数据通过 Windows 真实浏览器、三协议场景、在线/离线与 Linux 目录/race 检查。没有改核心 TLS 实现、ABI、SDK 或连接池；不重跑五平台 SDK、150 轮性能或小时观察。初次实施预算 30 分钟，外部运行排队单列；发现真实失败只补失败范围，保留失败记录。

这些是 Windows 指定语言/模式下冷导航的有界协议证据，不证明完整浏览器、其它平台、随机分布、ECH 内容、恢复连接、服务器信任锚协商或 ML-DSA 验证能力。历史兼容条目不因流程上线自动提升证据。

本地检查：

```sh
go test ./...
go vet ./...
python -m unittest discover -s tools/firefox -p 'test_*.py'
python -m unittest discover -s tools/chromium -p 'test_*.py'
python -m unittest discover -s tools/maintenance -p 'test_*.py'
```
