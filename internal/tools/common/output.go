package common

import (
	"encoding/json"
	"os"
)

type CIResult struct {
	OK      bool     `json:"ok"`
	Title   string   `json:"title"`
	Details []string `json:"details,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func PrintCIResult(ok bool, title string, details []string, err error) {
	result := CIResult{OK: ok, Title: title, Details: details}
	if err != nil {
		result.Error = err.Error()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}
