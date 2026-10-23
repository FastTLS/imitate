package recipes

// SafariHTTP2SettingsString HTTP/2 设置字符串格式
// 格式: "2:0;3:100;4:2097152;9:1|10420225|0:256:false|m,s,a,p"
// 注意: m,s,a,p 会自动推导为 :method,:scheme,:authority,:path
// 设置 ID 9 是 NO_RFC7540_PRIORITIES (Safari 扩展设置)
var SafariHTTP2SettingsString = legacyHTTP2("Safari")

func Safari(options *Options) {
	applyLegacy(options, "Safari", SafariHTTP2SettingsString)
}
