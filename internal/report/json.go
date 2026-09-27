package report

import (
	"encoding/json"

	"sni-scanner/internal/probe"
)

// JSONDoc is the machine-readable export shape.
type JSONDoc struct {
	Count   int            `json:"count"`
	Records []probe.Record `json:"records"`
}

// JSON renders up to limit records as indented JSON including every gate
// verdict and reason code. A limit of 0 means "no limit".
func JSON(records []probe.Record, limit int) ([]byte, error) {
	rows := records
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	doc := JSONDoc{Count: len(rows), Records: rows}
	if doc.Records == nil {
		doc.Records = []probe.Record{}
	}
	return json.MarshalIndent(doc, "", "  ")
}
