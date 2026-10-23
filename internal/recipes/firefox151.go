package recipes

// Firefox151HTTP2SettingsString Firefox 151 HTTP/2 配置
var Firefox151HTTP2SettingsString = legacyHTTP2("Firefox151")

// Firefox151JA3 Firefox 151 TLS JA3（含 compress_certificate/27 与 ffdhe 曲线）
const Firefox151JA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0"

// Firefox151 使用 Firefox 151 指纹
func Firefox151(options *Options) {
	applyLegacy(options, "Firefox151", Firefox151HTTP2SettingsString)
}
