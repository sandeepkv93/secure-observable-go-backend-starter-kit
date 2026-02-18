package validator

import "strings"

func NonEmpty(v string) bool { return strings.TrimSpace(v) != "" }
