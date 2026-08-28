package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist
var assets embed.FS

func Handler() http.Handler {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assetPath := strings.TrimPrefix(r.URL.Path, "/ui/")
		if assetPath == "" {
			r.URL.Path = "/"
			files.ServeHTTP(w, r)
			return
		}
		if _, err := fs.Stat(dist, path.Clean(assetPath)); err != nil {
			r.URL.Path = "/"
		} else {
			r.URL.Path = "/" + assetPath
		}
		files.ServeHTTP(w, r)
	})
}
