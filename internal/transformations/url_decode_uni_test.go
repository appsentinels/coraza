// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"fmt"
	"testing"

	"github.com/corazawaf/libinjection-go"
)

// TestURLDecodeUniNonLatinScriptRoundTrip guards against the bug fixed in
// this file: t:utf8toUnicode encodes non-ASCII runes as %uXXXX escapes, and
// t:urlDecodeUni is supposed to be its inverse. The old implementation only
// kept the lower byte of each %uXXXX escape, so any codepoint above U+00FF
// (e.g. Arabic, Cyrillic, CJK) was corrupted into unrelated ASCII bytes -
// which is what caused libinjection to see spurious SQL metacharacters in
// legitimate non-Latin text. See github.com/SpiderLabs/ModSecurity/issues/2100
// and github.com/owasp-modsecurity/ModSecurity/issues/2889 for the same bug
// reported against upstream ModSecurity (Russian and Chinese text).
func TestURLDecodeUniNonLatinScriptRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"arabic", "تقدم خدمات الليموزين"},
		{"arabic_alef_haa", "اح"}, // U+0627, U+062D - the exact chars misreported as ' and - in the write-up
		{"russian", "Это тест"},
		{"chinese", "开放智享套餐"},
		{"korean", "안녕하세요"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			escaped, changed, err := utf8ToUnicode(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatalf("expected utf8ToUnicode to change input %q", tc.input)
			}

			decoded, changed, err := urlDecodeUni(escaped)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatalf("expected urlDecodeUni to change input %q", escaped)
			}

			if decoded != tc.input {
				t.Errorf("round trip broken:\n  original: %q\n  escaped:  %q\n  decoded:  %q", tc.input, escaped, decoded)
			}
		})
	}
}

// TestURLDecodeUniPreservesModSecurityCompatBehavior locks in the two
// intentional exceptions that must NOT change: the Latin-1 range (U+0000-
// U+00FF) and the IIS full-width ASCII best-fit range (U+FF00-U+FFEF),
// which are covered byte-for-byte by testdata/urlDecodeUni.json (sourced
// from SpiderLabs/secrules-language-tests).
func TestURLDecodeUniPreservesModSecurityCompatBehavior(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"latin1_e_acute", "%u00e9", "\xe9"},              // é truncates to a single Latin-1 byte, unchanged
		{"fullwidth_quote_bestfit", "%uff07", "'"},        // fullwidth ' folds to ASCII ', unchanged (IIS best-fit)
		{"fullwidth_boundary_no_shift", "%uff7f", "\x7f"}, // outside the +0x20 shift window, unchanged
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decoded, _, err := urlDecodeUni(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if decoded != tc.expect {
				t.Errorf("input %q: got %q, want %q", tc.input, decoded, tc.expect)
			}
		})
	}
}

// TestArabicSQLiFalsePositiveRegression reproduces the reported production
// issue directly against libinjection: CRS's SQLi rule (942100) applies
// t:utf8toUnicode,t:urlDecodeUni,t:removeNulls before calling @detectSQLi.
// Before the fix, Arabic body text was corrupted into ASCII punctuation
// that libinjection flagged as SQL injection. A genuine SQLi payload run
// through the same chain must still be detected, so the fix doesn't trade
// a false positive for a false negative.
func TestArabicSQLiFalsePositiveRegression(t *testing.T) {
	applyCRSSQLiChain := func(v string) (string, error) {
		v, _, err := utf8ToUnicode(v)
		if err != nil {
			return "", err
		}
		v, _, err = urlDecodeUni(v)
		if err != nil {
			return "", err
		}
		v, _, err = removeNulls(v)
		if err != nil {
			return "", err
		}
		return v, nil
	}

	t.Run("arabic_text_is_not_flagged", func(t *testing.T) {
		// The exact "aiHints" field content from the reported false positive
		// (translates to "provides limousine services"). Before the fix,
		// this decoded to "*B/E ./E'* 'DDJEH2JF", which libinjection flags
		// as SQLi with fingerprint "sos".
		arabic := "تقدم خدمات الليموزين"
		out, err := applyCRSSQLiChain(arabic)
		if err != nil {
			t.Fatal(err)
		}
		if isSQLi, fingerprint := libinjection.IsSQLi(out); isSQLi {
			t.Errorf("false positive: Arabic text flagged as SQLi with fingerprint %q\ndecoded value: %q", fingerprint, out)
		}
	})

	t.Run("genuine_sqli_is_still_flagged", func(t *testing.T) {
		payload := "1' OR '1'='1"
		out, err := applyCRSSQLiChain(payload)
		if err != nil {
			t.Fatal(err)
		}
		if isSQLi, _ := libinjection.IsSQLi(out); !isSQLi {
			t.Errorf("false negative: genuine SQLi payload no longer flagged: %q", out)
		}
	})
}

func BenchmarkURLDecode(b *testing.B) {
	tests := []string{
		"",
		"helloworld",
		"hello+world",
		"%E3%83%8F%E3%83%AD%E3%83%BC%E3%83%AF%E3%83%BC%E3%83%AB%E3%83%89",
	}

	for _, mode := range []string{"normal", "unicode"} {
		f := urlDecode
		if mode == "unicode" {
			f = urlDecodeUni
		}
		for _, tc := range tests {
			tt := tc
			b.Run(fmt.Sprintf("%s/%s", mode, tt), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, _, err := f(tt); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
