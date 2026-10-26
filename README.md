# imitate

FastTLS 官方独立指纹生成库。模块为 `github.com/FastTLS/imitate`，只依赖 Go 标准库和 `github.com/FastTLS/fastls/profile` 小规范模块；不发送请求，不导入 Fastls 根包、fhttp、uTLS 或 quic-go。

## 安装

```sh
go get github.com/FastTLS/imitate@v0.1.0
```

需要 Go 1.26+。本库不联网获取或运行浏览器，不发送 HTTP 请求，不替代 TLS 传输。以下片段须配合 context、profile 与 imitate 的对应导入。

## 解析与使用

```go
provider := imitate.New()
result, err := provider.Resolve(context.Background(), profile.ResolveRequest{
    Selector: "chrome/155/windows",
    Policy:   profile.AllowCompatible,
})
```

结合 Fastls 使用时，`Use` 仍然位于请求库：

```go
import (
    fastls "github.com/FastTLS/fastls"
    "github.com/FastTLS/fastls/imitate"
    generators "github.com/FastTLS/imitate"
)

options := fastls.Options{FingerprintProvider: generators.New()}
match, err := imitate.Use(&options, "chrome/155/windows")
```

`WithProvider` 优先于 Options 中的提供者。显式提供者缺少记录时返回错误。Fastls 已移除冻结内置目录，Use 必须显式提供生成器或离线 Provider；用户仍可直接传入自定义 JA3、JA4R 或完整 Spec。生成器可并发复用，Resolve 返回独立数据，接收 context 取消，不联网选择最新版本。

当前可用配置以安装版本 Provider 的 `List` 为准，不把默认分支目录数量用于描述历史标签。只按规范 ID 解析；旧短名、旧平台/版本顺序、compat-v1 配置和 LegacyUAFirst 业务策略已移除。下游负责把旧名称或 UA 转成规范名称。请求 UA 不参与 Resolve 选择；用户可在 Fastls Options 中覆盖任意请求头的值，不改变协议参数与顺序。

UA 生成工具的范围不等于指纹目录的覆盖范围，以 List 返回的有限名称为准。已有配置使用记录的协议基线，不据此声称真实浏览器的全部指纹已经验证。

2026-10-25：正式目录的149个浏览器配置和3个原生配置全部返回完整 `Spec`，在线解析和离线导出不再通过 JA3/JA4R 重建协议。浏览器数据的维护入口是 `browser-specs.json`；`internal/recipes` 仅保留历史配方及身份工具，不再作为正式 TLS 目录的执行入口。迁移保留原有规范 ID；带 `legacy-ja4r` 的历史 ID 也承载完整 Spec。历史数据迁移不等于新增实机验证。缺少后端实现的历史声明通过 `capabilities.advertised_only` 明确保留，不宣称能够协商。

Edge 151–156 的 Windows 配置已按官方稳定版实测对齐 en-US 顶层导航请求头、HTTP/1 头名大小写及协议专属头，TLS 显式携带签名列表、GREASE 和扩展排序策略。离线包保留相同的每连接随机策略。独立浏览器证据在 `testdata/edge-windows-20261025.json`；其他平台、其他补丁版本、其他请求场景和 ECH 的完整随机分布尚未验证。ML-DSA 仅为线上声明，当前 uTLS 后端不能验证 ML-DSA 的 CertificateVerify；RSA/ECDSA 服务端握手另有回归覆盖。`RecordedOnly` 不因此把整个配置提升为完整实机一致。

该修订必须配套包含新协议头字段和能力检查的 profile/核心版本使用。本地跨仓构建使用工作区绑定；各模块正式发布前需要先发布匹配的 profile 和核心依赖，不能只升级数据包后假设旧后端支持新字段。

原生配置：

- `library/fastls/2/any/portable-h1`
- `library/fastls/2/any/portable-h2`
- `client/fastls-probe/1/any/portable-h1`

这些是本项目的可执行参数基线，支持 TLS1.2/1.3；不会冒充已采集的 curl、Python 或其它第三方客户端。library 基线不生成 UA/Client Hints；client 基线使用 `fastls-probe/1`。`browser` 包提供身份工具，`library` 和 `client` 包可直接生成完整 Spec。

`List` 返回该版本的全部规范 ID；新导出不包含旧别名和 compat-v1 配置。`Export` 导出带规范/提供者/数据修订的闭合 Bundle。导出行为以对应数据修订的 Spec 和测试为准；不要把单次导出结果当成真实浏览器完整随机分布的认证。

```sh
go run ./cmd/imitate-export -output fingerprints.json
go test ./...
```

导出文件通过 Fastls 的 `imitate.Register(data)` 得到隔离的离线 Provider，无全局注册、不加载脚本。数据仓库只维护证据和固定导出物，可执行配方的维护入口在本仓库。

稳定模块版本为 `v0.1.0`；默认分支的数据修订不等于已经发布的新模块版本。来源与第三方声明见 [NOTICE.md](NOTICE.md)。

用户请求头优先于默认值，包括显式空值。WithUserAgent 只覆盖 HTTP UA，不再重新生成其余身份头；未找到指纹返回错误。详见 [指纹与请求头](https://fasttls.github.io/concepts/fingerprints)。

## 详细文档与问题反馈

- [使用文档](https://fasttls.github.io/concepts/)：安装、功能、参数与排错。
- [版本与发布说明](https://github.com/FastTLS/imitate/releases)：正式版本、开发版本和产物边界。
- [问题反馈](https://github.com/FastTLS/imitate/issues)：请提供版本、系统架构、脱敏后的最小示例与错误；不要提交凭据、Cookie、私钥或个人数据。

## 开源协议与第三方声明

自有代码采用 [Apache-2.0](LICENSE)，来源与授权边界见 [NOTICE.md](NOTICE.md)。浏览器品牌属于各自权利人，配置身份不表示厂商认可。

## 使用边界与免责声明

仅在拥有权限的系统、数据和网络上使用，并遵守适用法律、服务条款及隐私要求。软件按许可证约定以“现状”提供，不承诺可用性、特定用途适用性、第三方服务放行、匿名性或与真实浏览器完全一致。浏览器名称和版本用于描述配置，不表示获得相应厂商认证或背书。部署方负责访问控制、密钥和个人信息保护、请求限额及数据备份；担保排除与责任限制以随附许可证及适用法律为准。本说明不改变许可证授予的权利或新增许可限制。
