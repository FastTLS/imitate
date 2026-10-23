package recipes

const chrome120Extension = "0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65037-65281"

// Chrome120HTTP2SettingsString HTTP/2 设置字符串格式
// 格式: "1:65536;2:0;4:6291456;6:262144|15663105|0:256:true|m,a,s,p"
// 注意: m,a,s,p 会自动推导为 :method,:authority,:scheme,:path
var Chrome120HTTP2SettingsString = legacyHTTP2("Chrome120")

func Chrome120(options *Options) {
	applyLegacy(options, "Chrome120", Chrome120HTTP2SettingsString)
}
