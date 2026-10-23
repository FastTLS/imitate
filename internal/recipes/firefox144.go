package recipes

// Firefox144HTTP2SettingsString HTTP/2 设置字符串格式
var Firefox144HTTP2SettingsString = legacyHTTP2("Firefox144")

func Firefox144(options *Options) {
	applyLegacy(options, "Firefox144", Firefox144HTTP2SettingsString)
}
