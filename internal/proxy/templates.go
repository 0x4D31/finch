package proxy

import (
	"embed"
	"html/template"
)

//go:embed templates/index.html
var templateFS embed.FS

var indexTmpl = template.Must(template.ParseFS(templateFS, "templates/index.html"))
