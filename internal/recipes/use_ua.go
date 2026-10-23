package recipes

func platformShort(platform string) string {
	switch platform {
	case "windows", "win":
		return "win"
	case "macos", "mac":
		return "mac"
	default:
		return platform
	}
}
