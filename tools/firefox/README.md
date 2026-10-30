# Firefox 配置候选更新

仅手动执行，范围为 Firefox 普通稳定版、Windows x64、zh-CN、无头冷连接。工作流 `browser-update.yml` 只有仓库读取权限；没有定时任务、PR、合并、标签或发布操作。

```powershell
python imitate/tools/firefox/update.py --repo imitate --core fastls --transport ftransport --lab fastls-lab --output run-159 --version 159.0 --sevenzip 'D:/Program Files/7-Zip/7z.exe'
```

省略 `--version` 时发现当前稳定版；发现后固定完整版本，不在执行中再次追随 latest。输入为经审查的四个仓库源码，工作流固定 core/transport/独立采集器提交；本地运行记录每仓提交及工作区内容摘要。需要 Node 24、Go 1.26.10、Python 3.11、7-Zip。浏览器从 Mozilla 官方 HTTPS 下载，以官方 HTTPS SHA512SUMS 验证后解包，不安装、不改系统信任或已有浏览器配置。HTTPS 校验和不等同于独立生产者签名验证。

每个场景取五个全新进程和配置目录，共 15 个样本：TLS 1.2/H1、TLS 1.3/H1、TLS 1.3/H2。完整 ClientHello、头序和 H2 帧参与对比；JA3 只是辅助诊断。缺样、重复、静态字段不稳定、未知扩展或不受后端支持的内容会阻断候选。新浏览器无法表达的能力不会被默默忽略。

采集证书例外仅存在于隔离的 BiDi 会话；库回放仍验证采集器 CA。随机 ECH 载荷、临时密钥内容与会话恢复不在等价声明内。H2 初始流编号与流级 WINDOW_UPDATE 等已知后端差异保留在报告和配置限制中，只能交付有明确边界的兼容候选，不能声称完整浏览器等价。

输入目录始终只读。目录投影及回放写入新的输出目录，最终生成：

- `update-report.json`：`candidate`、`no_change` 或 `blocked`，含精确来源、阶段、版本与限制。
- `semantic-diff.json`：忽略 JSON 对象键序，保留数组顺序、缺失/null/零值差异的字段路径。
- `bundles/firefox-windows.json`：现有 ProfileBundle v1 格式；`sha256` 固定精确 `spec_json` 字节。生产者身份与内容摘要分开判断。
- 完整观察输入、候选目录及在线/离线回放对比。失败保留证据，不替换有效配置。

已有同一完整版本、相同采集范围且 TLS/头及 H2 初始帧已回放验证的目录可以返回 `no_change`；`--force-capture` 强制重新采集。已登记的历史观察位于 `testdata/firefox/windows.json`，不能当作本次运行结果或当前活动目录已经更新的证明。

检查候选来源和限制后，再通过 Python/Node `ProfileBundle` 校验和 `ProfileStore` 导入、固定及回滚；导入、会话创建和请求均不会因此隐式联网。脚本不会自动启用候选。工作流原始证据保留 90 天，长期证据应另行归档。

```powershell
python -m unittest discover -s imitate/tools/firefox -p 'test_*.py' -v
```

新增浏览器家族、平台或协议必须有真实采集与回放证据。当前没有 Chromium/Safari 在线更新、ESR、移动端、H3 指纹或定时 PR 支持。

H2 候选会投影首流编号与 HEADERS 后的一次流窗口更新，非零字段要求 `http2.stream.v1`。回放从封存原始事件重新计算比较值，独立检查 stream ID；声明新能力的候选任何观测字段不符都阻断采用。该能力不会改写既有活动目录，旧限制及旧回放结论仍按各自来源保留。
