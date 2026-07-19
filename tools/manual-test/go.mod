module github.com/aegisgatesecurity/aegisgate-platform/tools/manual-test

go 1.26.5

// Only one third-party dependency: gorilla/websocket, used
// for Chrome DevTools Protocol communication. The Platform's
// main go.mod is unchanged.
require github.com/gorilla/websocket v1.5.3
