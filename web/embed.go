// Package web embeds the built React SPA (core D5). `npm run build` writes
// web/dist; until then only .gitkeep is embedded and the server serves a
// placeholder page.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built SPA rooted at dist/.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
