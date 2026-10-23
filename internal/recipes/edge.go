package recipes

// Edge 默认使用最新 Edge 160（TLS 为 Chrome150 基线，UA/Sec-CH-UA 为 160）
func Edge(options *Options) {
	EdgeVersion(options, ChromiumVersionDefault)
}
