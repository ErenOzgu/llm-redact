// Command llm-redact masks sensitive values in text before it goes to an LLM and puts them back in the answer.
package main

import (
	"os"

	"github.com/ErenOzgu/llm-redact/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}
