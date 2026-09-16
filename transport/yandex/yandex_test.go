package yandex

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// oldCursorRe is the regex that extractBase64String used before the
// allocation-free rewrite. It is kept here purely as the equivalence oracle:
// the rewrite must return exactly what this engine returns for every input.
var oldCursorRe = regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)

func oldExtractBase64String(response string) string {
	if strings.Contains(response, "saveChanges") {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(response, marker) + len(marker)
		if left < len(marker) {
			return ""
		}
		right := strings.Index(response[left:], `"`)
		if right == -1 {
			return ""
		}
		return response[left : left+right]
	}
	matches := oldCursorRe.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func TestExtractBase64String(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"typical cursor", `{"cursor":"AAAA;X123abc;def"}`, "X123abc;def"},
		{"single segment cursor", `{"cursor":"tok;payload123"}`, "payload123"},
		{"no semicolon", `{"cursor":"nopayload"}`, ""},
		{"empty before semicolon", `{"cursor":";payload"}`, ""},
		{"empty after semicolon", `{"cursor":"tok;"}`, ""},
		{"no closing quote", `{"cursor":"tok;payload`, ""},
		{"no marker", `{"other":"tok;payload"}`, ""},
		{"empty", "", ""},
		{"second occurrence wins when first is unusable",
			`{"cursor":";bad"} {"cursor":"ok;good"}`, "good"},
		{"quote inside pre-semicolon run is allowed",
			`{"cursor":"a"b;c"}`, "c"},
		{"cursor after unrelated text",
			`prefix junk {"cursor":"p1;SECRET_9"}`, "SECRET_9"},
		{"saveChanges branch takes precedence",
			`saveChanges {"cursor":"p1;fromCursor"} "excelAdditionalInfo":"fromExtra"`,
			"fromExtra"},
		{"saveChanges without additional info marker",
			`saveChanges {"cursor":"p1;fromCursor"}`, ""},
	}

	tpt := &YandexDocsTransport{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tpt.extractBase64String(tc.input); got != tc.want {
				t.Fatalf("extractBase64String(%q) = %q, want %q", tc.input, got, tc.want)
			}
			// The table itself must agree with the legacy engine too,
			// otherwise the expectations drifted from real behaviour.
			if legacy := oldExtractBase64String(tc.input); legacy != tc.want {
				t.Fatalf("table disagrees with legacy regex on %q: legacy=%q want=%q",
					tc.input, legacy, tc.want)
			}
		})
	}
}

// TestExtractBase64StringMatchesOldRegex differentially fuzzes the rewrite
// against the regex oracle over inputs drawn from an alphabet that actually
// exercises the grammar (marker bytes, quotes, semicolons).
func TestExtractBase64StringMatchesOldRegex(t *testing.T) {
	alphabet := []string{
		`"cursor":"`, `"`, `;`, `x`, `;`, `"`, ` `, `cursor`, `:`, `saveChanges`,
		`"excelAdditionalInfo":"`, "\n",
	}
	rng := rand.New(rand.NewSource(1))

	tpt := &YandexDocsTransport{}
	for i := 0; i < 200000; i++ {
		var b strings.Builder
		for n := rng.Intn(12); n >= 0; n-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		input := b.String()
		got := tpt.extractBase64String(input)
		want := oldExtractBase64String(input)
		if got != want {
			t.Fatalf("mismatch on %q: new=%q legacy=%q", input, got, want)
		}
	}
}

// BenchmarkExtractBase64String guards the hot path: this function runs per
// inbound doc frame, and the regex version cost ~24 MB of allocations per
// ~35 s of SpeedTest traffic on iPhone. Allocations per op must stay zero.
func BenchmarkExtractBase64String(b *testing.B) {
	frame := `{"a":".....` + strings.Repeat("z", 2048) +
		`....","cursor":"AAAA;BBBBCCCC;DDDD","b":"end"}`
	tpt := &YandexDocsTransport{}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if tpt.extractBase64String(frame) != "BBBBCCCC;DDDD" {
			b.Fatal("unexpected result")
		}
	}
}
