// RFC 9309 style parsing and matching.
//
// This file is used only when robots data is parsed with
// ParseOptions{RFC9309: true}. The legacy parser (parser.go, scanner.go) and
// legacy matching (Group.findRule) are untouched, so FromBytes/FromString and
// previously parsed objects keep their historical behaviour.
//
// Scope is intentionally limited to the robots.txt body: no HTTP fetching,
// caching or scheduling is implemented.
package robotstxt

import (
	"math"
	"strconv"
	"strings"
	"time"
)

type rfcTokenKind uint8

const (
	rfcLiteral rfcTokenKind = iota
	rfcWildcard
	rfcEndAnchor
)

type rfcToken struct {
	kind rfcTokenKind
	data []byte
}

// rfcRule is a single Allow/Disallow rule in RFC 9309 mode. The pattern is
// precompiled into tokens once at parse time and effectiveLen holds the
// number of "effective" bytes used for longest-rule precedence.
type rfcRule struct {
	allow        bool
	tokens       []rfcToken
	effectiveLen int
}

// parseRFC9309 parses a robots.txt body under the rules requested for the
// RFC 9309 mode. Malformed lines are skipped locally and never turn into a
// ParseError, so the returned error is always nil today; it is kept for
// signature symmetry with the legacy constructors.
func parseRFC9309(body []byte) (*RobotsData, error) {
	data := &RobotsData{
		rfc9309: true,
		groups:  make(map[string]*Group, 16),
	}

	// agents holds the normalized product tokens of the block currently being
	// built.
	//
	// A User-agent whose token is already in the set continues the current
	// block; this merges same-name groups, including case variants. Any other
	// User-agent starts a fresh block, which correctly ends an empty block
	// followed by another User-agent. Comments, blank lines, Host/Sitemap and
	// unknown fields do not appear in this switch and never change the state.
	// An empty trailing block is retained via eager group creation and later
	// shadows the "*" group.
	agents := make([]string, 0, 4)

	for _, rawLine := range splitRobotsLines(body) {
		line := trimRobotsSpace(rawLine)

		field, value, ok := strings.Cut(line, ":")
		if !ok {
			// Missing colon: the whole line is invalid and skipped without
			// touching group state.
			continue
		}
		field = strings.ToLower(trimRobotsSpace(field))
		// Inline comments start at a raw '#' inside the value; an encoded
		// %23 stays part of the value and never starts a comment.
		if i := strings.IndexByte(value, '#'); i >= 0 {
			value = value[:i]
		}
		value = trimRobotsSpace(value)

		switch field {
		case "user-agent":
			if value == "" {
				// Empty product token: invalid line, state unchanged.
				continue
			}
			key := strings.ToLower(value)
			if !containsAgent(agents, key) {
				// A new token starts the first block or a fresh subsequent
				// block; the previous block (even an empty one) is finalized.
				agents = make([]string, 0, 4)
				agents = append(agents, key)
			}
			// Eagerly create the group so an empty block is retained.
			data.rfcGroup(key)

		case "allow", "disallow":
			if len(agents) == 0 {
				// Rules before the first valid User-agent are ignored.
				continue
			}
			if value == "" {
				// Empty rules never participate in matching.
				continue
			}
			if value[0] != '/' && value[0] != '*' {
				// Non-empty rules must start with '/' or '*'.
				continue
			}
			rl := compileRFCRule(value, field == "allow")
			for _, key := range agents {
				g := data.rfcGroup(key)
				g.rfcRules = append(g.rfcRules, rl)
			}

		case "crawl-delay":
			if len(agents) == 0 {
				continue
			}
			d, ok := parseRobotsDelay(value)
			if !ok {
				continue
			}
			for _, key := range agents {
				data.rfcGroup(key).CrawlDelay = d
			}

		case "host":
			data.Host = value

		case "sitemap":
			if value == "" {
				continue
			}
			data.Sitemaps = append(data.Sitemaps, value)

		default:
			// Unknown fields are skipped without changing group state.
		}
	}

	return data, nil
}

func (r *RobotsData) rfcGroup(key string) *Group {
	g := r.groups[key]
	if g == nil {
		g = &Group{Agent: key, rfc9309: true}
		r.groups[key] = g
	}
	return g
}

func containsAgent(agents []string, key string) bool {
	for _, a := range agents {
		if a == key {
			return true
		}
	}
	return false
}

func parseRobotsDelay(value string) (time.Duration, bool) {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil || f < 0 || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return time.Duration(f * float64(time.Second)), true
}

// trimRobotsSpace trims only spaces and tabs, the colon/space grammar of
// RFC 9309. Newline characters have already been removed by line splitting.
func trimRobotsSpace(s string) string {
	start := 0
	for start < len(s) && isRobotsSpace(s[start]) {
		start++
	}
	end := len(s)
	for end > start && isRobotsSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isRobotsSpace(b byte) bool {
	return b == ' ' || b == '\t'
}

// splitRobotsLines splits on LF and CR (covering LF, CR and CRLF line
// endings) without collapsing empty lines, which must not change group state.
func splitRobotsLines(body []byte) []string {
	lines := strings.Split(string(body), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == '\n') {
			line = line[:len(line)-1]
		}
		for _, crLine := range strings.Split(line, "\r") {
			out = append(out, crLine)
		}
	}
	return out
}

// compileRFCRule turns a raw path pattern into matcher tokens and computes
// the effective length for precedence.
func compileRFCRule(raw string, allow bool) *rfcRule {
	rl := &rfcRule{allow: allow}
	var literal []byte
	flushLiteral := func() {
		if len(literal) > 0 {
			rl.tokens = append(rl.tokens, rfcToken{kind: rfcLiteral, data: literal})
			literal = nil
		}
	}

	for i := 0; i < len(raw); i++ {
		b := raw[i]
		switch {
		case b == '*':
			flushLiteral()
			rl.tokens = append(rl.tokens, rfcToken{kind: rfcWildcard})
		case b == '$' && i == len(raw)-1:
			// Only an unencoded '$' at the very end is an end anchor.
			flushLiteral()
			rl.tokens = append(rl.tokens, rfcToken{kind: rfcEndAnchor})
		default:
			if b == '%' && i+3 <= len(raw) && isHex(raw[i+1]) && isHex(raw[i+2]) {
				// Keep the whole percent-encoded triplet as literal data;
				// it is decoded at match time.
				literal = append(literal, raw[i:i+3]...)
				// A valid percent-encoded triplet counts as one effective byte.
				rl.effectiveLen++
				i += 2
			} else {
				literal = append(literal, b)
				// Literal byte, including an invalid '%' sequence and any byte
				// of a raw UTF-8 character.
				rl.effectiveLen++
			}
		}
	}
	flushLiteral()
	return rl
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// match reports whether the whole pattern matches path, always starting at
// the first byte of path.
func (rl *rfcRule) match(path string) bool {
	done := make(map[uint64]bool, len(rl.tokens)+1)
	var rec func(pos, tokenIdx int) bool
	rec = func(pos, tokenIdx int) bool {
		key := uint64(pos)<<32 | uint64(tokenIdx)
		if v, seen := done[key]; seen {
			return v
		}
		result := false
		switch {
		case tokenIdx == len(rl.tokens):
			// Pattern exhausted; remaining input bytes are fine.
			result = true
		case rl.tokens[tokenIdx].kind == rfcEndAnchor:
			// End anchor requires the input to be exhausted as well.
			result = pos == len(path) && tokenIdx+1 == len(rl.tokens)
		case rl.tokens[tokenIdx].kind == rfcWildcard:
			// '*' matches zero or more bytes; try every split point.
			for next := pos; next <= len(path); next++ {
				if rec(next, tokenIdx+1) {
					result = true
					break
				}
			}
		default:
			n := rfcLiteralMatchLen(path, pos, rl.tokens[tokenIdx].data)
			if n >= 0 {
				result = rec(pos+n, tokenIdx+1)
			}
		}
		done[key] = result
		return result
	}
	return rec(0, 0)
}

// rfcLiteralMatchLen returns the number of path bytes consumed by literal
// starting at path[pos], or -1 when it does not match.
func rfcLiteralMatchLen(path string, pos int, literal []byte) int {
	pi, li := pos, 0
	for li < len(literal) {
		if pi >= len(path) {
			return -1
		}
		pTriplet := decodePctTriplet(path, pi)
		lTriplet := decodePctTripletBytes(literal, li)

		if lTriplet >= 0 {
			if pTriplet >= 0 {
				// Two encoded triplets match only when they encode the same
				// byte. Hex letters are case-insensitive by construction.
				if pTriplet != lTriplet {
					return -1
				}
				pi += 3
				li += 3
				continue
			}
			// Encoded rule byte vs raw input byte. Encoded reserved
			// characters (e.g. %2F, %3F) stay isolated; unreserved and raw
			// UTF-8 bytes are equivalent to their encoded forms.
			if !rfcByteEquivalent(path[pi], byte(lTriplet)) {
				return -1
			}
			pi++
			li += 3
			continue
		}

		if pTriplet >= 0 {
			// Raw rule byte vs encoded input byte.
			if !rfcByteEquivalent(literal[li], byte(pTriplet)) {
				return -1
			}
			pi += 3
			li++
			continue
		}

		// Neither side is a valid triplet: a plain byte comparison. This also
		// makes an invalid '%' sequence match itself literally.
		if path[pi] != literal[li] {
			return -1
		}
		pi++
		li++
	}
	return pi - pos
}

// decodePctTriplet returns the decoded byte of a valid %HH triplet at s[pos],
// or -1 when the bytes at pos do not form a valid triplet.
func decodePctTriplet(s string, pos int) int {
	if pos+2 < len(s) && s[pos] == '%' && isHex(s[pos+1]) && isHex(s[pos+2]) {
		return int(hexToByte(s[pos+1], s[pos+2]))
	}
	return -1
}

// decodePctTripletBytes is the []byte variant used for rule patterns.
func decodePctTripletBytes(s []byte, pos int) int {
	if pos+2 < len(s) && s[pos] == '%' && isHex(s[pos+1]) && isHex(s[pos+2]) {
		return int(hexToByte(s[pos+1], s[pos+2]))
	}
	return -1
}

// rfcByteEquivalent compares a raw byte from one side with a decoded byte
// from a percent-encoded triplet on the other side. Besides unreserved ASCII
// and raw UTF-8 bytes, '*', '$' and '#' are explicitly equivalent to their
// encoded forms, while encoded reserved characters such as '/' and '?' are
// not equivalent to their structural raw forms.
func rfcByteEquivalent(raw, decoded byte) bool {
	// "raw" is a literal byte, "decoded" is the decoded byte of a percent
	// triplet on the other side. Equivalence holds only for unreserved ASCII
	// characters (where raw==decoded naturally) and raw UTF-8 bytes. The
	// explicit '*', '$' and '#' convention lets their encoded forms match a
	// raw literal of the same character. Other encoded reserved characters
	// such as '/' and '?' stay isolated from their structural raw forms.
	if decoded == '*' || decoded == '$' || decoded == '#' {
		return raw == decoded
	}
	return isRFCUnreserved(decoded) || decoded >= 0x80
}

func isRFCUnreserved(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '-', '.', '_', '~':
		return true
	}
	return false
}

func hexToByte(hi, lo byte) byte {
	hexVal := func(b byte) byte {
		switch {
		case b >= '0' && b <= '9':
			return b - '0'
		case b >= 'a' && b <= 'f':
			return b - 'a' + 10
		default:
			return b - 'A' + 10
		}
	}
	return hexVal(hi)<<4 | hexVal(lo)
}
