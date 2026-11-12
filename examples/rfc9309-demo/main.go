// Local, offline demo of the legacy mode versus the RFC 9309 mode. Run it
// with:
//
//	go run ./examples/rfc9309-demo
//
// It never performs any network access: all robots bodies and paths are
// defined below so the crawl scope can be inspected directly.
package main

import (
	"fmt"

	"github.com/temoto/robotstxt"
)

func main() {
	const robots = `User-Agent: ExampleBot
Disallow: /private
Allow: /private/public
Disallow: /assets/*.php$
Disallow: /a%2Fb
Disallow: /enc%2Astar

User-Agent: *
Disallow: /global
`

	checks := []struct {
		path  string
		agent string
	}{
		{"/private", "ExampleBot"},
		{"/private/public", "ExampleBot"},
		{"/private/secret", "ExampleBot"},
		{"/assets/app.php", "ExampleBot"},
		{"/assets/app.php?x=1", "ExampleBot"},
		{"/a%2Fb", "ExampleBot"},
		{"/a/b", "ExampleBot"},
		{"/enc*star", "ExampleBot"},
		{"/encXXstar", "ExampleBot"},
		{"/robots.txt", "ExampleBot"},
		// Exact agent match: ExampleBot-News falls back to "*" in RFC mode,
		// while the legacy mode uses prefix matching.
		{"/global", "ExampleBot-News"},
		{"/anything", "OtherBot"},
	}

	legacy, err := robotstxt.FromString(robots)
	if err != nil {
		panic(err)
	}
	modern, err := robotstxt.FromStringWithOptions(robots, robotstxt.ParseOptions{RFC9309: true})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%-22s %-18s %-10s %-10s\n", "path", "agent", "legacy", "RFC9309")
	for _, c := range checks {
		fmt.Printf("%-22s %-18s %-10t %-10t\n",
			c.path, c.agent,
			legacy.TestAgent(c.path, c.agent),
			modern.TestAgent(c.path, c.agent),
		)
	}
}
