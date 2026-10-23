package recipes

// Firefox158JA3 Firefox 158 TLS JA3
// 相对 151：移除扩展 27(compress_certificate)，曲线去掉 256/257(ffdhe)
const Firefox158JA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-65037,4588-29-23-24-25,0"

// Firefox158HTTP2SettingsString Firefox 158 HTTP/2（HEADERS Priority: weight=42, streamDep=0, exclusive=false）
var Firefox158HTTP2SettingsString = legacyHTTP2("Firefox158")

// FirefoxHTTP2SettingsString（默认最新）使用 Firefox 158
var FirefoxHTTP2SettingsString = Firefox158HTTP2SettingsString

// Firefox158 使用 Firefox 158 指纹
func Firefox158(options *Options) {
	applyLegacy(options, "Firefox158", Firefox158HTTP2SettingsString)
}

// Firefox 默认使用最新 Firefox 158 指纹
func Firefox(options *Options) {
	Firefox158(options)
}
