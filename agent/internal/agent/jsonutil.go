package agent

import (
	"encoding/json"
	"strings"
)

func toJSON(m map[string]string) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func jsonField(body []byte, field string) string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	s, _ := m[field].(string)
	return s
}

// clip shortens server text for log lines and strips control characters. The text never contains secrets: the
// server's problem responses do not echo credentials.
func clip(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
