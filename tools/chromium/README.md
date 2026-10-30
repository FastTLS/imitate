# Chrome／Edge 手动配置候选

使用 `python tools/browser_update.py --browser chrome` 或 `--browser edge`，后接必需的 `--repo`、`--core`、`--transport`、`--lab`、`--output` 源码与新输出目录，`--version` 固定完整四段版本。省略版本时只发现官方稳定版；不会修改活动配置、创建 PR、安装浏览器或发布。

首批仅 Windows x64、en-US、有界面最小化冷导航。每产品三个场景 TLS 1.2/H1、TLS 1.3/H1、TLS 1.3/H2，各五个独立新进程/配置。CDP 核对产品及完整版本，叶证书 SPKI 例外只用于本次本地采集器；没有修改系统信任。回放仍校验采集器 CA。

Chrome 使用 [官方 Chrome for Testing 清单](https://github.com/GoogleChromeLabs/chrome-for-testing)与 win64 ZIP；清单未提供厂商归档摘要，报告中的 SHA256 为本次 HTTPS 下载字节的本地记录，不能称为厂商校验和或归档签名。提取后核对有效 Google LLC Authenticode 和完整版本。Edge 使用[微软发行源](https://edgeupdates.microsoft.com/api/products?view=enterprise)的 MSI SHA256、大小及有效 Microsoft Corporation 可执行文件签名。签名失败、未知格式及错误版本均拒绝。解包复用了本工作区早期 Edge 工具的格式知识，BCJ2 实现在源码中有边界检查，不运行历史下载的解码程序。

比较保留完整静态 TLS 参数、扩展成员/次数、头顺序和 H2 帧；扩展随机顺序单独保存，GREASE 值、ECH 随机内容和临时密钥不作逐字节等价声明。新未知扩展、缺失/重复/不稳定样本、冷握手不符及后端不支持会生成 `blocked` 报告。`candidate` 提供 ProfileBundle v1、摘要、语义差异和限制，必须显式审核、导入、pin；失败不替换有效配置。ML-DSA 广告能力不能当成 CertificateVerify 支持，H2 流级差异继续保留。

`no_change` 仅接受目录中完整版本、平台、采集模式、三个传输和已回放字段均匹配的证据，不代表新后端认证。`--force-capture` 强制新样本；`--archive-cache` 仅复用匹配厂商 SHA256 的 Edge MSI，Chrome 不从外部归档缓存取文件。`--collector-cache` 为同源码和适配器的本地采集器提供摘要核对后的复用；任何输入或字节不符均拒绝。

每次输出 `update-report.json`、官方清单、构建身份、原始样本、观察、语义差异、回放报告及 Bundle；报告分别记录下载、采集器构建、采集与回放耗时。只读手动 Actions 入口为 `.github/workflows/browser-update.yml`。旧 `firefox_version` 参数仍可用于 Firefox，不能与其它产品或 `browser_version` 混用。
