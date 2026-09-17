//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type item struct{ domain, source, name string }

func main() {
	if len(os.Args) != 3 {
		panic("usage: gen <skill-dir> <out>")
	}
	root, out := os.Args[1], os.Args[2]
	files := []string{
		"ATTACK-CLASSES.md",
		"WEB-PROTOCOL-AND-AUTH.md",
		"CLIENT-SIDE.md",
		"RESOURCE-EXHAUSTION-AND-AVAILABILITY.md",
		"PROTOCOLS-RPC-AND-MESSAGING.md",
		"DATA-ISOLATION-AND-LIFECYCLE.md",
		"SUPPLY-CHAIN-AND-RELEASE.md",
		"CLOUD-AND-DEPLOYMENT.md",
		"AI-AND-LLM.md",
		"DESKTOP-MOBILE-AND-LOCAL-IPC.md",
		"MEMORY-SAFETY-AND-BINARY.md",
	}
	domains := map[string]string{
		"ATTACK-CLASSES.md":                       "Core",
		"WEB-PROTOCOL-AND-AUTH.md":                "HTTP, web and authentication",
		"CLIENT-SIDE.md":                          "Client-side and browser",
		"RESOURCE-EXHAUSTION-AND-AVAILABILITY.md": "Resource exhaustion and availability",
		"PROTOCOLS-RPC-AND-MESSAGING.md":          "Protocols, RPC and messaging",
		"DATA-ISOLATION-AND-LIFECYCLE.md":         "Data isolation and lifecycle",
		"SUPPLY-CHAIN-AND-RELEASE.md":             "Supply chain and release",
		"CLOUD-AND-DEPLOYMENT.md":                 "Cloud and deployment",
		"AI-AND-LLM.md":                           "AI, LLM and agents",
		"DESKTOP-MOBILE-AND-LOCAL-IPC.md":         "Desktop, mobile and local IPC",
		"MEMORY-SAFETY-AND-BINARY.md":             "Memory safety, binary and kernel",
	}
	re := regexp.MustCompile(`^\*\*([^*]+)\*\*(?:\s*\(.*\))?\s*$`)
	var items []item
	for _, file := range files {
		f, err := os.Open(filepath.Join(root, file))
		if err != nil {
			panic(err)
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			m := re.FindStringSubmatch(strings.TrimSpace(s.Text()))
			if len(m) != 2 {
				continue
			}
			name := strings.TrimSpace(m[1])
			if name == "Important" {
				continue
			}
			items = append(items, item{domains[file], file, name})
		}
		if err := s.Err(); err != nil {
			panic(err)
		}
		f.Close()
	}
	sort.SliceStable(items, func(i, j int) bool {
		order := func(source string) int {
			for n, f := range files {
				if f == source {
					return n
				}
			}
			return 999
		}
		if order(items[i].source) != order(items[j].source) {
			return order(items[i].source) < order(items[j].source)
		}
		return items[i].name < items[j].name
	})
	var b strings.Builder
	b.WriteString("// Code generated from cloudflare/security-audit-skill class names; DO NOT EDIT BY HAND.\n")
	b.WriteString("package coveragecatalog\n\n")
	b.WriteString("var skillClasses = []ClassDefinition{\n")
	for _, it := range items {
		fmt.Fprintf(&b, "\t{Domain: %q, Source: %q, Name: %q},\n", it.domain, it.source, it.name)
	}
	b.WriteString("}\n")
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, []byte(b.String()), 0644); err != nil {
		panic(err)
	}
	fmt.Printf("generated %d classes\n", len(items))
}
