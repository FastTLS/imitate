package recipes

// Firefox147 使用 Firefox 147 指纹（UA: rv:147.0）
// TLS/HTTP2 与 Firefox 144 保持一致，仅 UA 升级为 147
var Firefox147HTTP2SettingsString = legacyHTTP2("Firefox147")

func Firefox147(options *Options) {
	applyLegacy(options, "Firefox147", Firefox147HTTP2SettingsString)
}
