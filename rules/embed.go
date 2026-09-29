/*
Hiten | 2026
embed.go

Embeds the default rule set so the binary works without the
rules directory next to it.
*/

package rules

import _ "embed"

//go:embed default.yaml
var Default []byte
