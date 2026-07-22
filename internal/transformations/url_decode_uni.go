// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"sync/atomic"
	"unicode/utf8"

	"github.com/appsentinels/coraza/v3/internal/strings"
)

// legacyURLDecodeUni switches urlDecodeUni back to the pre-fix behavior,
// which truncates any %uXXXX codepoint outside the Latin-1 and IIS
// full-width ASCII ranges to its lower byte, discarding the upper byte.
// That behavior corrupts non-Latin scripts (Arabic, Cyrillic, CJK, ...)
// into unrelated ASCII punctuation and can cause false positives in
// downstream detectors such as libinjection.
//
// This is a process-wide switch, not a per-WAF-instance one: the
// transformation registry is a single map shared by every WAF instance in
// the process, so EnableLegacyURLDecodeUni affects urlDecodeUni for every
// WAF/policy running in the process, not just the one whose WAFConfig
// requested it. It is meant as an emergency rollback lever (e.g. to
// immediately restore byte-for-byte ModSecurity-compatible behavior if the
// fixed behavior is ever found to regress some detection), not a
// per-tenant setting. There is no corresponding "disable" call by design:
// once engaged for a process, it stays engaged until the process restarts
// without requesting it again, so one WAF instance's default config can
// never silently undo another instance's explicit opt-in.
var legacyURLDecodeUni atomic.Bool

// EnableLegacyURLDecodeUni turns on the legacy (pre-fix) urlDecodeUni
// behavior for the remainder of the process's lifetime. See
// legacyURLDecodeUni for the scoping caveats.
func EnableLegacyURLDecodeUni() {
	legacyURLDecodeUni.Store(true)
}

func urlDecodeUni(data string) (string, bool, error) {
	for i := 0; i < len(data); i++ {
		if data[i] == '%' || data[i] == '+' {
			return inplaceUniDecode(data, []byte(data), i, legacyURLDecodeUni.Load()), true, nil
		}
	}
	return data, false, nil
}

// inplaceUniDecode decodes data in place. legacy selects which behavior is
// used for %uXXXX codepoints outside the Latin-1 and IIS full-width ASCII
// ranges: the corrected UTF-8 encoding (legacy=false, the default) or the
// pre-fix lower-byte truncation (legacy=true, see legacyURLDecodeUni). It
// is a plain parameter rather than reading the global switch internally so
// both code paths can be tested directly without touching process-wide state.
func inplaceUniDecode(input string, d []byte, pos int, legacy bool) string {
	inputLen := len(d)
	i := pos
	c := pos

	for i < inputLen {
		if d[i] == '%' {
			if (i+1 < inputLen) && ((input[i+1] == 'u') || (input[i+1] == 'U')) {
				/* Character is a percent sign. */
				/* IIS-specific %u encoding. */
				if i+5 < inputLen {
					/* We have at least 4 data bytes. */
					if (strings.ValidHex(input[i+2])) && (strings.ValidHex(input[i+3])) && (strings.ValidHex(input[i+4])) && (strings.ValidHex(input[i+5])) {
						hi := strings.X2c(input[i+2:])
						lo := strings.X2c(input[i+4:])

						switch {
						case legacy:
							/* Pre-fix ModSecurity-compatible behavior: always
							 * truncate to the lower byte, discarding the
							 * higher byte, with the same full-width ASCII
							 * (ff01-ff5e) exception. See
							 * legacyURLDecodeUni for why this exists. */
							d[c] = lo
							if hi == 0xff && lo > 0x00 && lo < 0x5f {
								d[c] += 0x20
							}
							c++
						case hi == 0x00:
							/* Codepoint fits in a single byte (Latin-1
							 * range, U+0000-U+00FF): keep it as-is. */
							d[c] = lo
							c++
						case hi == 0xff:
							/* Full width ASCII (U+FF00-U+FFEF) mirrors IIS's
							 * best-fit decoding onto standard-width ASCII;
							 * ff01-ff5e additionally need 0x20 added. */
							d[c] = lo
							if lo > 0x00 && lo < 0x5f {
								d[c] += 0x20
							}
							c++
						default:
							/* Any other codepoint: emit its actual UTF-8
							 * encoding instead of truncating to the lower
							 * byte and discarding the higher byte, which
							 * corrupts non-Latin scripts (e.g. Arabic,
							 * Cyrillic, CJK) into unrelated ASCII
							 * punctuation and causes false positives in
							 * downstream detection (e.g. libinjection).
							 * See github.com/SpiderLabs/ModSecurity/issues/2100. */
							code := rune(hi)<<8 | rune(lo)
							c += utf8.EncodeRune(d[c:], code)
						}
						i += 6
					} else {
						/* Invalid data, skip %u. */
						d[c] = input[i]
						i++
						c++
						d[c] = input[i]
						c++
						i++
					}
				} else {
					/* Not enough bytes (4 data bytes), skip %u. */
					d[c] = input[i]
					i++
					c++
					d[c] = input[i]
					i++
					c++
				}
			} else {
				/* Standard URL encoding. */
				/* Are there enough bytes available? */
				if i+2 < inputLen {
					/* Yes. */

					/* Decode a %xx combo only if it is valid.
					 */
					c1 := input[i+1]
					c2 := input[i+2]

					if strings.ValidHex(c1) && strings.ValidHex(c2) {
						d[c] = strings.X2c(input[i+1:])
						c++
						i += 3
					} else {
						/* Not a valid encoding, skip this % */
						d[c] = input[i]
						i++
						c++
					}
				} else {
					/* Not enough bytes available, skip this % */
					d[c] = input[i]
					i++
					c++
				}
			}
		} else {
			/* Character is not a percent sign. */
			if input[i] == '+' {
				d[c] = ' '
				c++
			} else {
				d[c] = input[i]
				c++
			}

			i++
		}
	}

	return strings.WrapUnsafe(d[0:c])
}
