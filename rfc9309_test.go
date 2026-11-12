package robotstxt

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustRFC(t *testing.T, body string) *RobotsData {
	t.Helper()
	r, err := FromStringWithOptions(body, ParseOptions{RFC9309: true})
	require.NoError(t, err)
	require.NotNil(t, r)
	return r
}

// TestRFCGroupMergeAndEmpty covers same-name group merging across case
// differences, full (non-prefix) agent matching, empty group retention and
// fallback to the "*" group.
func TestRFCGroupMergeAndEmpty(t *testing.T) {
	t.Parallel()
	const body = `User-Agent: ExampleBot
User-Agent: EXAMPLEBOT
Disallow: /a

User-Agent: examplebot
Disallow: /b

User-Agent: EmptyBot

User-Agent: *
Disallow: /star
`
	r := mustRFC(t, body)

	type tcase struct {
		agent string
		path  string
		allow bool
	}
	cases := []tcase{
		// Rules from both ExampleBot groups are merged.
		{"ExampleBot", "/a", false},
		{"examplebot", "/b", false},
		{"EXAMPLEBOT", "/a/x", false},
		// No prefix matching: ExampleBot does not match ExampleBot-News.
		{"ExampleBot-News", "/a", true},
		// Dedicated group wins over "*": ExampleBot has no /star rule.
		{"ExampleBot", "/star", true},
		// Empty dedicated group is retained and shadows "*".
		{"EmptyBot", "/star", true},
		{"EmptyBot", "/anything", true},
		// No dedicated group: fall back to "*".
		{"OtherBot", "/star", false},
		{"OtherBot", "/other", true},
	}
	for _, c := range cases {
		t.Run(c.agent+"|"+c.path, func(t *testing.T) {
			assert.Equal(t, c.allow, r.TestAgent(c.path, c.agent))
			assert.Equal(t, c.allow, r.FindGroup(c.agent).Test(c.path))
		})
	}

	// Same-name agents with different case resolve to one merged group.
	require.Contains(t, r.groups, "examplebot")
	assert.Len(t, r.groups["examplebot"].rfcRules, 2)
	require.Contains(t, r.groups, "emptybot")
	assert.Empty(t, r.groups["emptybot"].rfcRules)
}

// TestRFCParseRecovery verifies malformed lines are skipped locally without
// changing group state or breaking later valid lines, and never produce
// ParseError.
func TestRFCParseRecovery(t *testing.T) {
	t.Parallel()
	const body = `Disallow: /before-any-ua
GarbageLineWithoutColon
User-Agent:
Unknown-Directive: value
# a comment : with colon

User-Agent: bot
Disallow:
Disallow: relative/path
Disallow: /good
Allow: /good/open
Crawl-delay: not-a-number
Crawl-delay: 2.5

Disallow /missing-colon
User-Agent: next
Disallow: /next
`
	r, err := FromBytesWithOptions([]byte(body), ParseOptions{RFC9309: true})
	require.NoError(t, err)

	assert.False(t, r.TestAgent("/good", "bot"))
	assert.True(t, r.TestAgent("/good/open", "bot"))
	assert.True(t, r.TestAgent("/relative/path", "bot"))
	assert.Equal(t, 2500*time.Millisecond, r.FindGroup("bot").CrawlDelay)

	// The malformed "Disallow /missing-colon" line does not open or seal
	// any group, so the following User-Agent starts its own fresh group.
	assert.False(t, r.TestAgent("/next", "next"))
	assert.True(t, r.TestAgent("/good", "next"))

	// A rule before the first valid User-agent is ignored entirely.
	assert.True(t, r.TestAgent("/before-any-ua", "bot"))
}

// TestRFCSealAfterEmptyOrIgnoredRule ensures that a well-formed (colon
// present) Allow/Disallow line seals the current group even when its value
// is empty or the path is ignored.
func TestRFCSealAfterEmptyOrIgnoredRule(t *testing.T) {
	t.Parallel()
	const body = `User-Agent: first
User-Agent: shared
Disallow:
User-Agent: shared
Disallow: /only-second
`
	r := mustRFC(t, body)
	assert.True(t, r.TestAgent("/only-second", "first"))
	assert.False(t, r.TestAgent("/only-second", "shared"))

	// A path that is syntactically ignored (does not start with '/' or '*')
	// still terminates the current group's User-agent collection.
	const bodyIgnored = `User-Agent: a
User-Agent: b
Disallow: relative-ignored
User-Agent: b
Disallow: /second-block
`
	r2 := mustRFC(t, bodyIgnored)
	assert.True(t, r2.TestAgent("/second-block", "a"))
	assert.False(t, r2.TestAgent("/second-block", "b"))
	assert.True(t, r2.TestAgent("/relative-ignored", "a"))
}

// TestRFCTestAgentAndGroupAgree locks the requirement that TestAgent and
// FindGroup(agent).Test always return the same answer for the same inputs.
func TestRFCTestAgentAndGroupAgree(t *testing.T) {
	t.Parallel()
	r := mustRFC(t, "User-Agent: bot\nDisallow: /x\nAllow: /x/y\nUser-Agent: *\nDisallow: /z\n")
	paths := []string{"/x", "/x/y", "/x/y/z", "/z", "/robots.txt", "/other?a=1", "/X"}
	agents := []string{"bot", "BOT", "other", "bot-extra"}
	for _, agent := range agents {
		for _, path := range paths {
			direct := r.TestAgent(path, agent)
			grouped := r.FindGroup(agent).Test(path)
			assert.Equal(t, direct, grouped, "agent=%q path=%q", agent, path)
		}
	}
}

// TestRFCQueryString verifies the query string is kept verbatim, including
// parameter order.
func TestRFCQueryString(t *testing.T) {
	t.Parallel()
	const body = `User-Agent: *
Disallow: /search?q=go
Disallow: /fixed?a=1&b=2
Allow: /allowed?x=1
`
	r := mustRFC(t, body)
	type tcase struct {
		path  string
		allow bool
	}
	cases := []tcase{
		{"/search?q=go", false},
		{"/search?q=go&p=2", false},
		{"/search?q=other", true},
		{"/fixed?b=2&a=1", true}, // parameters are not reordered
		{"/fixed?a=1&b=2", false},
		{"/allowed?x=1", true},
		{"/allowed?x=2", true},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			assert.Equal(t, c.allow, r.TestAgent(c.path, "bot"))
		})
	}
}

// TestRFCLineEndings verifies LF, CR and CRLF are all accepted.
func TestRFCLineEndings(t *testing.T) {
	t.Parallel()
	bodies := []string{
		"User-Agent: bot\nDisallow: /a\n",
		"User-Agent: bot\rDisallow: /a\r",
		"User-Agent: bot\r\nDisallow: /a\r\n",
	}
	for i, body := range bodies {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			r := mustRFC(t, body)
			assert.False(t, r.TestAgent("/a", "bot"))
			assert.True(t, r.TestAgent("/b", "bot"))
		})
	}
}

// TestRFCPathMatching is the main table-driven matcher test: encoding
// equivalence, reserved-character isolation, encoded special symbols,
// anchoring, wildcards, precedence and default allow.
func TestRFCPathMatching(t *testing.T) {
	t.Parallel()
	const body = `User-Agent: *
Disallow: /plain
Disallow: /fish*
Disallow: /*.php$
Disallow: /end$
Disallow: /star*star
Disallow: /a%2Fb
Disallow: /q%3Fx
Disallow: /enc%2Astar
Disallow: /enc%24dollar
Disallow: /enc%23hash
Disallow: /pct%252Fdeep
Disallow: /unreserved/%7Ehome
Disallow: /utf8/中
Disallow: /bad%zzpercent
Disallow: /longest/x
Allow: /longest/x
Disallow: /eqlen/disallow
Allow: /eqlen/allow
`
	r := mustRFC(t, body)
	type tcase struct {
		name  string
		path  string
		allow bool
	}
	cases := []tcase{
		// Start-anchored matching, no matching from the middle.
		{"plain-hit", "/plain", false},
		{"plain-prefix", "/plain/sub", false},
		{"plain-no-middle", "/x/plain", true},
		{"wildcard-zero", "/fish", false},
		{"wildcard-multi", "/fish/salmon.html", false},
		{"php-end-anchor", "/index.php", false},
		{"php-anchor-miss-query", "/index.php?x=1", true},
		{"php-anchor-miss-slash", "/index.php/", true},
		{"end-anchor", "/end", false},
		{"end-anchor-miss", "/ending", true},
		{"dollar-literal-elsewhere", "/x$/y", true},
		{"wildcard-both-sides", "/starXXstar", false},

		// Reserved characters stay structurally isolated.
		{"encoded-slash-hit", "/a%2Fb", false},
		{"encoded-slash-not-raw", "/a/b", true},
		{"raw-slash-still-matches-encoded-text", "/a%2fb", false},
		{"encoded-question-hit", "/q%3Fx", false},
		{"encoded-question-not-raw", "/q?x", true},

		// Encoded special symbols are literals, not syntax.
		{"encoded-star-literal", "/enc*star", false},
		{"encoded-star-no-wildcard", "/encXXstar", true},
		{"encoded-dollar-literal", "/enc$dollar", false},
		{"encoded-hash-literal", "/enc#hash", false},

		// Only one encoding layer is processed.
		{"double-encoded-hit", "/pct%252Fdeep", false},
		{"double-encoded-not-single", "/pct%2Fdeep", true},
		{"double-encoded-not-raw", "/pct/deep", true},

		// Unreserved ASCII percent-encoding is equivalent, hex case-insensitive.
		{"unreserved-tilde-encoded", "/unreserved/~home", false},
		{"unreserved-tilde-raw-input", "/unreserved/%7ehome", false},

		// Raw UTF-8 bytes are equivalent to their percent-encoding.
		{"utf8-raw", "/utf8/\u4e2d", false},
		{"utf8-encoded", "/utf8/%E4%B8%AD", false},
		{"utf8-encoded-lower-hex", "/utf8/%e4%b8%ad", false},
		{"utf8-other-char", "/utf8/\u6587", true},

		// Invalid percent sequences match literally and never panic.
		{"invalid-pct-hit", "/bad%zzpercent", false},
		{"invalid-pct-miss", "/bad%ZZpercent", true},

		// Longest effective rule wins; equal effective length -> Allow.
		{"longest-allow-wins", "/longest/x", true},
		{"eqlen-allow", "/eqlen/allow", true},
		{"eqlen-disallow", "/eqlen/disallow", false},

		// No match means allow.
		{"default-allow", "/totally/unrelated", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.allow, r.TestAgent(c.path, "bot"), "path=%q", c.path)
		})
	}
}

// TestRFCEffectiveLength verifies precedence counting: percent triplets count
// as one byte, UTF-8 counts by raw bytes, wildcards and the end anchor count
// zero, while regex-escaped string lengths are never used.
func TestRFCEffectiveLength(t *testing.T) {
	t.Parallel()
	const body = `User-Agent: *
Disallow: /ab
Allow: /a%62
Disallow: /w*
Allow: /wild
Disallow: /anchor$
Allow: /anchor
`
	r := mustRFC(t, body)
	// /a%62 has effective length 3, equal to literal /ab (3): Allow wins.
	assert.True(t, r.TestAgent("/ab", "bot"))
	// "wild" (4 effective) beats "w*" (1 effective, wildcard ignored).
	assert.True(t, r.TestAgent("/wild", "bot"))
	// /anchor (7) and /anchor$ (7, '$' counts zero) tie on /anchor:
	// equal effective length -> Allow.
	assert.True(t, r.TestAgent("/anchor", "bot"))
	// Only plain /anchor matches /anchors as a prefix (still Allow).
	assert.True(t, r.TestAgent("/anchors", "bot"))
}

// TestRFCRobotsTxtAlwaysAllowed covers the mandatory /robots.txt exception.
func TestRFCRobotsTxtAlwaysAllowed(t *testing.T) {
	t.Parallel()
	r := mustRFC(t, "User-Agent: *\nDisallow: /\n")
	assert.True(t, r.TestAgent("/robots.txt", "bot"))
	assert.False(t, r.TestAgent("/robots.txt/extra", "bot"))
	assert.False(t, r.TestAgent("/", "bot"))

	// An empty dedicated group still allows /robots.txt.
	r2 := mustRFC(t, "User-Agent: bot\n")
	assert.True(t, r2.TestAgent("/robots.txt", "bot"))
}

// TestRFCEmptyAndBarePaths covers empty bodies and non-slash paths.
func TestRFCEmptyAndBarePaths(t *testing.T) {
	t.Parallel()
	empty, err := FromBytesWithOptions(nil, ParseOptions{RFC9309: true})
	require.NoError(t, err)
	assert.True(t, empty.TestAgent("/anything", "bot"))

	r := mustRFC(t, "User-Agent: *\nDisallow: /ok\n")
	// Paths are documented to start with '/'; a bare path simply matches no
	// rule and is allowed.
	assert.True(t, r.TestAgent("ok", "bot"))
}

// TestRFCFieldCaseAndComments checks field-name case handling, inline
// comments started only by raw '#', and Host/Sitemap extraction.
func TestRFCFieldCaseAndComments(t *testing.T) {
	t.Parallel()
	const body = `user-agent: BOT # inline comment is not part of the token
dIsAlLoW: /secret # block this
allow: /%23not-comment
Host: example.com
Sitemap: https://example.com/sitemap.xml
`
	r := mustRFC(t, body)
	assert.False(t, r.TestAgent("/secret", "bot"))
	assert.True(t, r.TestAgent("/public", "bot"))
	assert.True(t, r.TestAgent("/#not-comment", "bot"))
	assert.Equal(t, "example.com", r.Host)
	require.Len(t, r.Sitemaps, 1)
	assert.Equal(t, "https://example.com/sitemap.xml", r.Sitemaps[0])
	assert.Equal(t, "bot", r.FindGroup("BOT").Agent)
}

// TestRFCCrawlDelayLastWins verifies the last legal Crawl-delay wins and
// illegal values are ignored.
func TestRFCCrawlDelayLastWins(t *testing.T) {
	t.Parallel()
	const body = `User-Agent: bot
Crawl-delay: 1
Crawl-delay: nope
Crawl-delay: 4.5
`
	r := mustRFC(t, body)
	assert.Equal(t, 4500*time.Millisecond, r.FindGroup("bot").CrawlDelay)
}

// TestRFCOptionsModeIsPerObject ensures zero-value options keep legacy
// behaviour, each object stores its own mode, and there is no global switch.
func TestRFCOptionsModeIsPerObject(t *testing.T) {
	t.Parallel()
	const body = `User-Agent: ExampleBot
Disallow: /a

User-Agent: *
Disallow: /star
`
	legacy, err := FromBytesWithOptions([]byte(body), ParseOptions{})
	require.NoError(t, err)
	legacyString, err := FromStringWithOptions(body, ParseOptions{RFC9309: false})
	require.NoError(t, err)
	modern := mustRFC(t, body)

	assert.False(t, legacy.rfc9309)
	assert.False(t, legacyString.rfc9309)
	assert.True(t, modern.rfc9309)

	// Legacy keeps prefix matching: ExampleBot-News selects the ExampleBot
	// group; modern requires an exact full token match and falls back to "*".
	assert.False(t, legacy.TestAgent("/a", "ExampleBot-News"))
	assert.False(t, legacyString.TestAgent("/a", "ExampleBot-News"))
	assert.True(t, modern.TestAgent("/a", "ExampleBot-News"))
	assert.False(t, modern.TestAgent("/star", "ExampleBot-News"))

	// The modern object never affects the legacy object and vice versa.
	assert.False(t, legacy.TestAgent("/a", "ExampleBot"))
	assert.False(t, modern.TestAgent("/a", "ExampleBot"))
}

// TestLegacyRegression locks in the historical group selection and path
// matching behaviour, including ParseError preservation.
func TestLegacyRegression(t *testing.T) {
	t.Parallel()
	const prefixBody = `user-agent: wall-e
disallow: /
user-agent: *
allow: /`
	legacy, err := FromString(prefixBody)
	require.NoError(t, err)
	// Prefix-based group selection is a legacy trait.
	assert.Equal(t, "wall-e", legacy.FindGroup("wall-e-extra").Agent)
	assert.False(t, legacy.TestAgent("/anything", "wall-e-extra"))
	assert.Equal(t, "*", legacy.FindGroup("eve").Agent)

	// Legacy wildcard/dollar regex matching stays unchanged.
	wild, err := FromString("User-Agent: *\nDisallow: /path*l$")
	require.NoError(t, err)
	assert.Equal(t, "/path.*l$", wild.groups["*"].rules[0].pattern.String())
	assert.False(t, wild.TestAgent("/path/to/url", "bot"))

	// ParseError behaviour is preserved in legacy mode.
	_, err = FromString("Disallow: /\nUser-agent: bot")
	require.Error(t, err)
	_, ok := err.(*ParseError)
	assert.True(t, ok)

	// RFC mode never returns ParseError for the same body.
	_, err = FromStringWithOptions("Disallow: /\nUser-agent: bot", ParseOptions{RFC9309: true})
	assert.NoError(t, err)
}

// TestRFCConcurrentMixedModes uses old and new objects concurrently to prove
// the mode lives on each object and there is no shared mutable switch.
func TestRFCConcurrentMixedModes(t *testing.T) {
	t.Parallel()
	const body = `User-Agent: Bot
Disallow: /private
User-Agent: *
Disallow: /global
`
	legacy, err := FromString(body)
	require.NoError(t, err)
	modern := mustRFC(t, body)

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				path := "/private/" + strconv.Itoa(j)
				if legacy.TestAgent(path, "Bot") {
					t.Error("legacy object changed behaviour")
				}
				if modern.TestAgent(path, "Bot") {
					t.Error("modern object changed behaviour")
				}
				// Modern: Bot-X has no dedicated group, so "*" blocks /global.
				// Legacy: Bot-X prefix-matches the Bot group, which has no
				// /global rule, so it is allowed.
				if modern.TestAgent("/global", "Bot-X") {
					t.Error("modern prefix match leaked")
				}
				if !legacy.TestAgent("/global", "Bot-X") {
					t.Error("legacy group selection changed")
				}
				_ = modern.FindGroup("bot").Test(path)
			}
		}(i)
	}
	wg.Wait()
}
