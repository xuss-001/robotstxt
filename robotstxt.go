// Package robotstxt implements the robots.txt Exclusion Protocol
// as specified in http://www.robotstxt.org/wc/robots.html
// with various extensions.
package robotstxt

// Comments explaining the logic are taken from either the Google's spec:
// https://developers.google.com/webmasters/control-crawl-index/docs/robots_txt

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type RobotsData struct {
	Host     string
	Sitemaps []string

	// private
	allowAll    bool
	disallowAll bool
	rfc9309     bool
	groups      map[string]*Group
}

// ParseOptions controls parsing behaviour of FromBytesWithOptions and
// FromStringWithOptions. The zero value preserves the historical
// interpretation used by FromBytes/FromString.
//
// When RFC9309 is true, the robots.txt body is parsed and matched according
// to the rules implemented for RFC 9309 (see package-level documentation
// in rfc9309.go). Each parsed RobotsData stores its own mode, so old and
// new objects can be used concurrently in the same process; there is no
// global switch.
type ParseOptions struct {
	RFC9309 bool
}

type Group struct {
	rules      []*rule
	Agent      string
	CrawlDelay time.Duration

	disallowAll bool
	rfc9309     bool
	rfcRules    []*rfcRule
}

type rule struct {
	path    string
	allow   bool
	pattern *regexp.Regexp
}

type ParseError struct {
	Errs []error
}

func newParseError(errs []error) *ParseError {
	return &ParseError{errs}
}

func (e ParseError) Error() string {
	var b bytes.Buffer

	b.WriteString("Parse error(s): " + "\n")
	for _, er := range e.Errs {
		b.WriteString(er.Error() + "\n")
	}
	return b.String()
}

// Unwrap returns the underlying errors, compatible with errors.Is
// and errors.As from the standard library (Go 1.20+).
func (e ParseError) Unwrap() []error {
	return e.Errs
}

var allowAll = &RobotsData{allowAll: true}
var disallowAll = &RobotsData{disallowAll: true}
var emptyGroup = &Group{}
var emptyDisallowGroup = &Group{disallowAll: true}

func FromStatusAndBytes(statusCode int, body []byte) (*RobotsData, error) {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return FromBytes(body)

	// From https://developers.google.com/webmasters/control-crawl-index/docs/robots_txt
	//
	// Google treats all 4xx errors in the same way and assumes that no valid
	// robots.txt file exists. It is assumed that there are no restrictions.
	// This is a "full allow" for crawling. Note: this includes 401
	// "Unauthorized" and 403 "Forbidden" HTTP result codes.
	case statusCode >= 400 && statusCode < 500:
		return allowAll, nil

	// From Google's spec:
	// Server errors (5xx) are seen as temporary errors that result in a "full
	// disallow" of crawling.
	case statusCode >= 500 && statusCode < 600:
		return disallowAll, nil
	}

	return nil, errors.New("Unexpected status: " + strconv.Itoa(statusCode))
}

func FromStatusAndString(statusCode int, body string) (*RobotsData, error) {
	return FromStatusAndBytes(statusCode, []byte(body))
}

func FromResponse(res *http.Response) (*RobotsData, error) {
	if res == nil {
		// Edge case, if res is nil, return nil data
		return nil, nil
	}
	buf, e := ioutil.ReadAll(res.Body)
	if e != nil {
		return nil, e
	}
	return FromStatusAndBytes(res.StatusCode, buf)
}

func FromBytes(body []byte) (r *RobotsData, err error) {
	var errs []error

	// special case (probably not worth optimization?)
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return allowAll, nil
	}

	sc := newByteScanner("bytes", true)
	//sc.Quiet = !print_errors
	sc.feed(body, true)
	tokens := sc.scanAll()

	// special case worth optimization
	if len(tokens) == 0 {
		return allowAll, nil
	}

	r = &RobotsData{}
	parser := newParser(tokens)
	r.groups, r.Host, r.Sitemaps, errs = parser.parseAll()
	if len(errs) > 0 {
		return nil, newParseError(errs)
	}

	return r, nil
}

func FromString(body string) (r *RobotsData, err error) {
	return FromBytes([]byte(body))
}

// FromBytesWithOptions parses robots.txt body with explicit parsing options.
// ParseOptions{RFC9309: false} (the zero value) is fully equivalent to
// FromBytes and keeps the historical behaviour, including ParseError.
// ParseOptions{RFC9309: true} enables the RFC 9309 style parsing and
// matching implemented in this package; malformed local lines are skipped
// instead of producing ParseError.
func FromBytesWithOptions(body []byte, opts ParseOptions) (r *RobotsData, err error) {
	if opts.RFC9309 {
		return parseRFC9309(body)
	}
	return FromBytes(body)
}

// FromStringWithOptions is the string counterpart of FromBytesWithOptions.
func FromStringWithOptions(body string, opts ParseOptions) (r *RobotsData, err error) {
	return FromBytesWithOptions([]byte(body), opts)
}

func (r *RobotsData) TestAgent(path, agent string) bool {
	if r.allowAll {
		return true
	}
	if r.disallowAll {
		return false
	}

	// Find a group of rules that applies to this agent
	// From Google's spec:
	// The user-agent is non-case-sensitive.
	g := r.FindGroup(agent)
	return g.Test(path)
}

// FindGroup searches block of declarations for specified user-agent.
// From Google's spec:
// Only one group of group-member records is valid for a particular crawler.
// The crawler must determine the correct group of records by finding the group
// with the most specific user-agent that still matches. All other groups of
// records are ignored by the crawler. The user-agent is non-case-sensitive.
// The order of the groups within the robots.txt file is irrelevant.
func (r *RobotsData) FindGroup(agent string) (ret *Group) {
	if r.rfc9309 {
		// RFC 9309: case-insensitive full product-token match, no prefix
		// matching. A specific group never merges with the "*" group.
		if g := r.groups[strings.ToLower(agent)]; g != nil {
			return g
		}
		if g := r.groups["*"]; g != nil {
			return g
		}
		if r.disallowAll {
			return emptyDisallowGroup
		}
		return emptyGroup
	}

	var prefixLen int

	agent = strings.ToLower(agent)
	if ret = r.groups["*"]; ret != nil {
		// Weakest match possible
		prefixLen = 1
	}
	for a, g := range r.groups {
		if a != "*" && strings.HasPrefix(agent, a) {
			if l := len(a); l > prefixLen {
				prefixLen = l
				ret = g
			}
		}
	}

	if ret == nil {
		if r.disallowAll {
			return emptyDisallowGroup
		} else {
			return emptyGroup
		}
	}
	return
}

func (g *Group) Test(path string) bool {
	if g.disallowAll {
		return false
	}
	if g.rfc9309 {
		return g.testRFC9309(path)
	}
	if r := g.findRule(path); r != nil {
		return r.allow
	}

	// From Google's spec:
	// By default, there are no restrictions for crawling for the designated crawlers.
	return true
}

func (g *Group) testRFC9309(path string) bool {
	// RFC 9309: requests to /robots.txt itself are always allowed.
	if path == "/robots.txt" {
		return true
	}

	var best *rfcRule
	for _, rl := range g.rfcRules {
		if rl.match(path) && (best == nil || rl.effectiveLen > best.effectiveLen ||
			(rl.effectiveLen == best.effectiveLen && rl.allow)) {
			best = rl
		}
	}
	if best == nil {
		// No rule matched: allow by default.
		return true
	}
	return best.allow
}

// From Google's spec:
// The path value is used as a basis to determine whether or not a rule applies
// to a specific URL on a site. With the exception of wildcards, the path is
// used to match the beginning of a URL (and any valid URLs that start with the
// same path).
//
// At a group-member level, in particular for allow and disallow directives,
// the most specific rule based on the length of the [path] entry will trump
// the less specific (shorter) rule. The order of precedence for rules with
// wildcards is undefined.
func (g *Group) findRule(path string) (ret *rule) {
	var prefixLen int

	for _, r := range g.rules {
		if r.pattern != nil {
			if r.pattern.MatchString(path) {
				// Consider this a match equal to the length of the pattern.
				// From Google's spec:
				// The order of precedence for rules with wildcards is undefined.
				if l := len(r.pattern.String()); l > prefixLen {
					prefixLen = l
					ret = r
				}
			}
		} else if r.path == "/" && prefixLen == 0 {
			// Weakest match possible
			prefixLen = 1
			ret = r
		} else if strings.HasPrefix(path, r.path) {
			if l := len(r.path); l > prefixLen {
				prefixLen = l
				ret = r
			}
		}
	}
	return
}
