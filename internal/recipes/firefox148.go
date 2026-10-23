package recipes

// Firefox148 使用 Firefox 147 指纹（UA: rv:147.0）
// TLS/HTTP2 与 Firefox 144 保持一致，仅 UA 升级为 147
var Firefox148HTTP2SettingsString = legacyHTTP2("Firefox148")

func Firefox148(options *Options) {
	applyLegacy(options, "Firefox148", Firefox148HTTP2SettingsString)
}
