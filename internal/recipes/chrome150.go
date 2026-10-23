package recipes

// Chrome150JA3 Chrome / Chromium / Edge / Opera 共用的 TLS JA3（含 ML-DSA 签名算法对应的 ClientHello 形态）
// 扩展集合与 Chrome142 相同，顺序不同；JA4R 另含 0904/0905/0906
const Chrome150JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-11-0-17613-5-45-23-65037-16-27-13-10-18-35-51-43-41,4588-29-23-24,0"

// Chrome150HTTP2SettingsString 与现代 Chromium 一致（无 MAX_CONCURRENT_STREAMS，无 HeaderPriority）
var Chrome150HTTP2SettingsString = legacyHTTP2("Chrome150")

// Chrome150 使用 Chromium 150 系共享 TLS/HTTP2 指纹（默认最新 Chromium 系基线）
func Chrome150(options *Options) {
	applyLegacy(options, "Chrome150", Chrome150HTTP2SettingsString)
}
