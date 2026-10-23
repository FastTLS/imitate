# imitate

FastTLS 官方独立指纹生成库。模块为 `github.com/FastTLS/imitate`，只依赖 Go 标准库和 `github.com/FastTLS/fastls/profile` 小规范模块；不发送请求，不导入 Fastls 根包、fhttp、uTLS 或 quic-go。

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

当前目录包含149个浏览器规范配置和3个原生配置，共152条。只按规范 ID 解析；旧短名、旧平台/版本顺序、compat-v1 配置和 LegacyUAFirst 业务策略已移除。下游负责把旧名称或 UA 转成规范名称。请求 UA 不参与 Resolve 选择；用户可在 Fastls Options 中覆盖任意请求头的值，不改变协议参数与顺序。

UA 生成工具的范围不等于指纹目录的覆盖范围，以 List 返回的有限名称为准。已有配置使用记录的协议基线，不据此声称真实浏览器的全部指纹已经验证。

原生配置：

- `library/fastls/2/any/portable-h1`
- `library/fastls/2/any/portable-h2`
- `client/fastls-probe/1/any/portable-h1`

这些是本项目的可执行参数基线，支持 TLS1.2/1.3；不会冒充已采集的 curl、Python 或其它第三方客户端。library 基线不生成 UA/Client Hints；client 基线使用 `fastls-probe/1`。`browser` 包提供身份工具，`library` 和 `client` 包可直接生成完整 Spec。

`List` 返回152个规范 ID；新导出不包含旧别名和 compat-v1 配置。`Export` 导出带规范/提供者/数据修订的闭合 Bundle。导出中历史随机扩展固定为一种允许的排列，不携带连接密钥；在线 Resolve 保留原随机约束。

```sh
go run ./cmd/imitate-export -output fingerprints.json
go test ./...
```

导出文件通过 Fastls 的 `imitate.Register(data)` 得到隔离的离线 Provider，无全局注册、不加载脚本。数据仓库只维护证据和固定导出物，可执行配方的维护入口在本仓库。

当前为尚未发布Go模块版本的开发候选。跨仓验收可使用显式文件模块代理或由CI固定源码提交，公共 go.mod 没有本机 replace；规范子模块须先发布，随后发布 fhttp/核心/生成器。开发分支用于联调，尚未打发布标签。来源见 `NOTICE.md`，正式发布前须确认授权与许可证。

用户请求头优先于默认值，包括显式空值。WithUserAgent 只覆盖 HTTP UA，不再重新生成其余身份头；未找到指纹返回错误。详细分工见工作区 FASTLS_V2_REQUEST_HEADERS.md。
