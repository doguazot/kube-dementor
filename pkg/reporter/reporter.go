package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatHTML Format = "html"
)

func Write(w io.Writer, report *scanner.ScanReport, format Format, color bool) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, report)
	case FormatHTML:
		return writeHTML(w, report)
	case FormatText, "":
		return writeText(w, report, color)
	}
	return fmt.Errorf("unknown format: %s", format)
}

func writeJSON(w io.Writer, r *scanner.ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
