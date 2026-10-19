package web

import "embed"

//go:embed index.html app.js style.css countries.geojson
var FS embed.FS
