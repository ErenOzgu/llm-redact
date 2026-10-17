// Package cli implements the llm-redact command line.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/ErenOzgu/llm-redact/internal/redact"
)

const usage = `llm-redact: mask sensitive values before text goes to an LLM, and put them back in the answer.

Usage:
  llm-redact redact  [options] [file]           print the text with sensitive values replaced by [[KIND_N]]
  llm-redact restore -map FILE [file]           put the original values back into an answer
  llm-redact check   [options] file...          list what would be masked (exit 1 if anything); never prints values
  llm-redact ask     [options] -prompt TEXT [file]
                                                redact, send to the Anthropic Messages API, restore the answer
  llm-redact list                               the kinds of value that are recognised
  llm-redact version

Options for redact, check and ask:
  -map FILE        keep the placeholder-to-value table in FILE (mode 0600); reused when it exists
  -skip KINDS      comma separated kinds not to mask, for example HOST,USER
  -only KINDS      mask only these kinds
  -keep VALUE      a value that is never masked (repeatable)
  -rule KIND=RE    an extra pattern (repeatable); a capture group, if any, marks the part to mask
  -rules FILE      extra patterns as JSON: [{"kind":"SERIAL","pattern":"SN-([0-9]{8})","group":1}]
  -force           go on although the input already contains text that looks like a placeholder
  -max-bytes N     refuse input larger than N bytes (default 67108864)

Run 'llm-redact COMMAND -h' for the options of one command.
`

// Run executes the command line and returns the exit status: 0 success, 1 something was found
// (check) or an answer could not be fully restored (-strict), 2 usage or I/O error.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "redact":
		return runRedact(args[1:], stdin, stdout, stderr)
	case "restore":
		return runRestore(args[1:], stdin, stdout, stderr)
	case "check":
		return runCheck(args[1:], stdin, stdout, stderr)
	case "ask":
		return runAsk(args[1:], stdin, stdout, stderr)
	case "list":
		return runList(stdout)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "llm-redact", version)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "llm-redact: unknown command %q\n\n%s", args[0], usage)
	return 2
}

// ---- shared options --------------------------------------------------------------------------------

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

type common struct {
	mapPath  string
	skip     string
	only     string
	keep     listFlag
	rules    listFlag
	rulesF   string
	force    bool
	maxBytes int64
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.mapPath, "map", "", "placeholder table file")
	fs.StringVar(&c.skip, "skip", "", "kinds not to mask")
	fs.StringVar(&c.only, "only", "", "mask only these kinds")
	fs.Var(&c.keep, "keep", "value that is never masked")
	fs.Var(&c.rules, "rule", "extra pattern KIND=REGEX")
	fs.StringVar(&c.rulesF, "rules", "", "extra patterns as a JSON file")
	fs.BoolVar(&c.force, "force", false, "go on despite placeholder-like text in the input")
	fs.Int64Var(&c.maxBytes, "max-bytes", 64<<20, "refuse larger input")
}

func splitKinds(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, k := range strings.Split(s, ",") {
		if k = strings.ToUpper(strings.TrimSpace(k)); k != "" {
			m[k] = true
		}
	}
	return m
}

func (c *common) options() (redact.Options, error) {
	opts := redact.Options{Only: splitKinds(c.only), Skip: splitKinds(c.skip), AllowAnyway: c.force}
	if len(c.keep) > 0 {
		opts.Keep = map[string]bool{}
		for _, k := range c.keep {
			opts.Keep[k] = true
		}
	}
	for _, spec := range c.rules {
		kind, pattern, ok := strings.Cut(spec, "=")
		if !ok {
			return opts, fmt.Errorf("-rule %q: want KIND=REGEX", spec)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return opts, fmt.Errorf("-rule %q: %w", spec, err)
		}
		group := 0
		if re.NumSubexp() > 0 {
			group = 1
		}
		opts.Custom = append(opts.Custom, redact.CustomRule{Kind: strings.ToUpper(kind), Pattern: pattern, Group: group})
	}
	if c.rulesF != "" {
		data, err := os.ReadFile(c.rulesF)
		if err != nil {
			return opts, err
		}
		var rules []redact.CustomRule
		if err := json.Unmarshal(data, &rules); err != nil {
			return opts, fmt.Errorf("%s: %w", c.rulesF, err)
		}
		opts.Custom = append(opts.Custom, rules...)
	}
	return opts, nil
}

// readAll reads the file named by args (or stdin for none or "-"), at most max bytes.
func readAll(args []string, stdin io.Reader, max int64) (string, string, error) {
	name := "-"
	if len(args) > 0 {
		name = args[0]
	}
	var r io.Reader = stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return "", name, err
		}
		defer f.Close()
		r = f
	} else {
		name = "<stdin>"
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return "", name, err
	}
	if int64(len(data)) > max {
		return "", name, fmt.Errorf("%s is larger than %d bytes (raise -max-bytes)", name, max)
	}
	return string(data), name, nil
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "llm-redact: %v\n", err)
	return 2
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("llm-redact "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// ---- redact -------------------------------------------------------------------------------------

func runRedact(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var c common
	var out string
	var stats, quiet bool
	fs := newFlagSet("redact", stderr)
	c.register(fs)
	fs.StringVar(&out, "o", "", "write the result to this file instead of stdout")
	fs.BoolVar(&stats, "stats", false, "print how many values of each kind were masked, to stderr")
	fs.BoolVar(&quiet, "q", false, "no warnings")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	opts, err := c.options()
	if err != nil {
		return fail(stderr, err)
	}
	text, _, err := readAll(fs.Args(), stdin, c.maxBytes)
	if err != nil {
		return fail(stderr, err)
	}
	m, err := loadMap(c.mapPath)
	if err != nil {
		return fail(stderr, err)
	}
	r, err := redact.New(opts, m)
	if err != nil {
		return fail(stderr, err)
	}
	masked, found, err := r.Redact(text)
	if err != nil {
		return fail(stderr, err)
	}
	// The table goes to disk first: output without a table cannot be restored.
	if c.mapPath != "" {
		if err := m.Save(c.mapPath); err != nil {
			return fail(stderr, err)
		}
	} else if len(found) > 0 && !quiet {
		fmt.Fprintln(stderr, "llm-redact: no -map given, so the masking cannot be undone")
	}
	if out != "" {
		if err := os.WriteFile(out, []byte(masked), 0o644); err != nil {
			return fail(stderr, err)
		}
	} else if _, err := io.WriteString(stdout, masked); err != nil {
		return fail(stderr, err)
	}
	if stats {
		printStats(stderr, found)
	}
	return 0
}

func loadMap(path string) (*redact.Mapping, error) {
	if path == "" {
		return redact.NewMapping(), nil
	}
	return redact.LoadMapping(path)
}

func printStats(w io.Writer, found []redact.Finding) {
	counts := map[string]int{}
	for _, f := range found {
		counts[f.Kind]++
	}
	if len(counts) == 0 {
		fmt.Fprintln(w, "llm-redact: nothing masked")
		return
	}
	parts := []string{}
	for _, k := range redact.SortedKinds(counts) {
		parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
	}
	fmt.Fprintf(w, "llm-redact: masked %d values (%s)\n", len(found), strings.Join(parts, ", "))
}

// ---- restore ------------------------------------------------------------------------------------

func runRestore(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var mapPath string
	var strict bool
	var maxBytes int64
	fs := newFlagSet("restore", stderr)
	fs.StringVar(&mapPath, "map", "", "placeholder table file (required)")
	fs.BoolVar(&strict, "strict", false, "exit 1 if a placeholder in the text is not in the table")
	fs.Int64Var(&maxBytes, "max-bytes", 64<<20, "refuse larger input")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if mapPath == "" {
		return fail(stderr, errors.New("restore needs -map FILE"))
	}
	if _, err := os.Stat(mapPath); err != nil {
		return fail(stderr, err)
	}
	m, err := redact.LoadMapping(mapPath)
	if err != nil {
		return fail(stderr, err)
	}
	text, _, err := readAll(fs.Args(), stdin, maxBytes)
	if err != nil {
		return fail(stderr, err)
	}
	restored, unknown := redact.Restore(text, m)
	if _, err := io.WriteString(stdout, restored); err != nil {
		return fail(stderr, err)
	}
	if len(unknown) > 0 {
		fmt.Fprintf(stderr, "llm-redact: %d placeholder(s) not in the table were left as they are: %s\n", len(unknown), strings.Join(unknown, " "))
		if strict {
			return 1
		}
	}
	return 0
}

// ---- check --------------------------------------------------------------------------------------

type checkFinding struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Col    int    `json:"col"`
	Kind   string `json:"kind"`
	Length int    `json:"length"`
}

func runCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var c common
	var asJSON bool
	fs := newFlagSet("check", stderr)
	c.register(fs)
	fs.BoolVar(&asJSON, "json", false, "machine readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	opts, err := c.options()
	if err != nil {
		return fail(stderr, err)
	}
	r, err := redact.New(opts, nil)
	if err != nil {
		return fail(stderr, err)
	}
	files := fs.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}
	var all []checkFinding
	for _, name := range files {
		text, shown, err := readAll([]string{name}, stdin, c.maxBytes)
		if err != nil {
			return fail(stderr, err)
		}
		for _, f := range r.Scan(text) {
			all = append(all, checkFinding{File: shown, Line: f.Line, Col: f.Col, Kind: f.Kind, Length: f.End - f.Start})
		}
	}
	if asJSON {
		if all == nil {
			all = []checkFinding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(all)
	} else {
		for _, f := range all {
			fmt.Fprintf(stdout, "%s:%d:%d: %s (%d bytes)\n", f.File, f.Line, f.Col, f.Kind, f.Length)
		}
	}
	if len(all) > 0 {
		return 1
	}
	return 0
}

// ---- list ---------------------------------------------------------------------------------------

var kindHelp = map[string]string{
	"PRIVKEY": "PEM private key blocks, also truncated ones",
	"TOKEN":   "API keys and tokens with a known shape (AWS, GitHub, GitLab, Slack, Google, Anthropic, OpenAI, Stripe, npm, PyPI, ...), JWTs, Bearer and Basic credentials",
	"CRED":    "user:password inside a URL",
	"SECRET":  "the value after password, secret, token, api_key, ... in key=value, key: value and JSON",
	"HASH":    "crypt(3) password hashes ($6$..., $y$...)",
	"COOKIE":  "values in Cookie and Set-Cookie header lines",
	"CARD":    "payment card numbers (Luhn checked)",
	"EMAIL":   "e-mail addresses",
	"IPV4":    "IPv4 addresses (loopback, 0.0.0.0 and broadcast are left alone)",
	"IPV6":    "IPv6 addresses",
	"MAC":     "MAC addresses",
	"USER":    "user names in /home/NAME, C:\\Users\\NAME, user=NAME and ssh log lines (system accounts are left alone)",
	"HOST":    "host names under common or private top-level domains (well-known public sites are left alone)",
}

func runList(stdout io.Writer) int {
	for _, k := range redact.Kinds {
		fmt.Fprintf(stdout, "%-8s %s\n", k, kindHelp[k])
	}
	return 0
}
