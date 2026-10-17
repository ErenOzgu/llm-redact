package redact

import (
	"net"
	"regexp"
	"strings"
)

// span is a byte range of the input that gets replaced.
type span struct {
	start, end int
	kind       string
	prio       int
}

// A detector finds the parts of a text that must be masked.
type detector struct {
	kind string
	prio int
	find func(s string) []span
}

// Priorities decide which detector wins when two want overlapping text.
const (
	prioPrivKey = 100
	prioCustom  = 95
	prioToken   = 90
	prioURLCred = 80
	prioSecret  = 70
	prioCard    = 60
	prioEmail   = 50
	prioNet     = 40
	prioUser    = 35
	prioHost    = 30
)

// Kinds lists the built-in kinds in the order they are documented.
var Kinds = []string{"PRIVKEY", "TOKEN", "CRED", "SECRET", "HASH", "COOKIE", "CARD", "EMAIL", "IPV4", "IPV6", "MAC", "USER", "HOST"}

func builtinDetectors() []detector {
	return []detector{
		{"PRIVKEY", prioPrivKey, findPrivKey},
		{"TOKEN", prioToken, findTokens},
		{"CRED", prioURLCred, findURLCred},
		{"SECRET", prioSecret, findSecretKV},
		{"HASH", prioSecret, findCryptHash},
		{"COOKIE", prioSecret, findCookie},
		{"CARD", prioCard, findCard},
		{"EMAIL", prioEmail, findEmail},
		{"IPV4", prioNet, findIPv4},
		{"IPV6", prioNet, findIPv6},
		{"MAC", prioNet, findMAC},
		{"USER", prioUser, findUser},
		{"HOST", prioHost, findHost},
	}
}

// groupSpans turns every match of re into a span over capture group g (0 = the whole match).
func groupSpans(re *regexp.Regexp, s, kind string, prio, g int) []span {
	var out []span
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		a, b := m[2*g], m[2*g+1]
		if a < 0 || b <= a {
			continue
		}
		out = append(out, span{a, b, kind, prio})
	}
	return out
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// ---- private keys ----------------------------------------------------------------------------

var privKeyRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)

// A key that was cut off in the middle (a truncated log) has a BEGIN line and no END line.
var privKeyOpenRE = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:\\n|\r?\n)?(?:[A-Za-z0-9+/=]{16,}(?:\\n|\r?\n)?)*`)

func findPrivKey(s string) []span {
	out := groupSpans(privKeyRE, s, "PRIVKEY", prioPrivKey, 0)
	return append(out, groupSpans(privKeyOpenRE, s, "PRIVKEY", prioPrivKey, 0)...)
}

// ---- tokens with a recognisable shape ------------------------------------------------------------

var tokenREs = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b`),          // AWS access key id
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`),                                  // GitHub
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{50,}\b`),                                // GitHub fine-grained
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`),                                      // GitLab
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),                                  // Slack
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),                                       // Google API key
	regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`),                                      // Google OAuth access token
	regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`),                                     // Anthropic
	regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}`),                               // OpenAI style
	regexp.MustCompile(`\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b`),                        // Stripe
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),                                         // npm
	regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}`),                                       // PyPI
	regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`),                                         // Hugging Face
	regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`),                    // SendGrid
	regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{20,}`),                                   // Docker Hub
	regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`),                                         // DigitalOcean
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
}

// The credential after "Bearer" or "Basic" in an Authorization header.
var authSchemeRE = regexp.MustCompile(`(?i)\b(?:bearer|basic)[ \t]+([A-Za-z0-9._~+/=-]{12,})`)

func findTokens(s string) []span {
	var out []span
	for _, re := range tokenREs {
		out = append(out, groupSpans(re, s, "TOKEN", prioToken, 0)...)
	}
	return append(out, groupSpans(authSchemeRE, s, "TOKEN", prioToken, 1)...)
}

// ---- credentials in URLs ---------------------------------------------------------------------------

var urlCredRE = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,20}://([^\s/@:]+:[^\s/@]+)@`)

func findURLCred(s string) []span { return groupSpans(urlCredRE, s, "CRED", prioURLCred, 1) }

// ---- key = value secrets ---------------------------------------------------------------------------

// The key has to END in one of the words, so "api_key" and "db_password" match and "tokenizer" and
// "password_file" do not.
var secretKeyRE = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?key|encryption[_-]?key|signing[_-]?key|credential|authorization)s?)(["']?[ \t]*(?:=|:)[ \t]*)`)

// Values that are references or empty markers, not secrets.
var secretNonValues = map[string]bool{
	"true": true, "false": true, "null": true, "none": true, "nil": true, "yes": true, "no": true,
	"required": true, "optional": true, "string": true, "int": true, "bool": true, "redacted": true,
	"undefined": true, "empty": true, "unset": true,
}

func findSecretKV(s string) []span {
	var out []span
	for _, m := range secretKeyRE.FindAllStringSubmatchIndex(s, -1) {
		valStart := m[1]
		if valStart >= len(s) {
			continue
		}
		var a, b int
		switch c := s[valStart]; c {
		case '"', '\'':
			a = valStart + 1
			b = a
			for b < len(s) && s[b] != c && s[b] != '\n' {
				if s[b] == '\\' && b+1 < len(s) {
					b++
				}
				b++
			}
		case '{', '[', '\n', '\r':
			continue
		default:
			a = valStart
			b = a
			for b < len(s) && !strings.ContainsRune(" \t\r\n\"',;&)]}", rune(s[b])) {
				b++
			}
		}
		if b <= a {
			continue
		}
		val := s[a:b]
		// "Authorization: Bearer <credential>": the scheme word is not the secret, the credential is
		// (the token detector takes it).
		if isReference(val) || secretNonValues[strings.ToLower(val)] || authSchemes[strings.ToLower(val)] {
			continue
		}
		out = append(out, span{a, b, "SECRET", prioSecret})
	}
	return out
}

var authSchemes = map[string]bool{"bearer": true, "basic": true, "digest": true, "negotiate": true}

// isReference reports whether a value is a variable reference or a template, such as ${DB_PASSWORD},
// $DB_PASSWORD, {{ .Values.password }} or %(password)s: those are not secrets.
func isReference(v string) bool {
	switch {
	case strings.HasPrefix(v, "${"), strings.HasPrefix(v, "{{"), strings.HasPrefix(v, "%("), strings.HasPrefix(v, "<"):
		return true
	case strings.HasPrefix(v, "$") && len(v) > 1 && isWordByte(v[1]):
		return true
	case exactPlaceholderRE.MatchString(v):
		return true
	}
	return false
}

// ---- password hashes and cookies ---------------------------------------------------------------------

var cryptHashRE = regexp.MustCompile(`\$(?:1|2[aby]?|5|6|y|7)\$[./A-Za-z0-9$,=-]{8,}`)

func findCryptHash(s string) []span { return groupSpans(cryptHashRE, s, "HASH", prioSecret, 0) }

var cookieRE = regexp.MustCompile(`(?im)^[ \t]*(?:set-)?cookie:[ \t]*(\S.*?)[ \t]*$`)

var cookiePairRE = regexp.MustCompile(`([A-Za-z0-9_.%-]+)=([^;\s]+)`)

// Attributes of a Set-Cookie header that are settings, not values.
var cookieAttributes = setOf("path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "priority", "version")

// findCookie masks the value of every name=value pair in a Cookie or Set-Cookie header line.
func findCookie(s string) []span {
	var out []span
	for _, h := range cookieRE.FindAllStringSubmatchIndex(s, -1) {
		base := h[2]
		line := s[h[2]:h[3]]
		for _, m := range cookiePairRE.FindAllStringSubmatchIndex(line, -1) {
			if cookieAttributes[strings.ToLower(line[m[2]:m[3]])] {
				continue
			}
			out = append(out, span{base + m[4], base + m[5], "COOKIE", prioSecret})
		}
	}
	return out
}

// ---- payment cards ----------------------------------------------------------------------------------

// A chain of digit groups joined by single spaces or dashes: 4111 1111 1111 1111.
var digitChainRE = regexp.MustCompile(`[0-9]+(?:[ -][0-9]+)*`)
var digitGroupRE = regexp.MustCompile(`[0-9]+`)

func findCard(s string) []span {
	var out []span
	for _, chain := range digitChainRE.FindAllStringIndex(s, -1) {
		groups := digitGroupRE.FindAllStringIndex(s[chain[0]:chain[1]], -1)
		// Try every run of whole groups, earliest first: a number in front of a card number must not hide it.
		for i := 0; i < len(groups); i++ {
			start := chain[0] + groups[i][0]
			if start > 0 && isWordByte(s[start-1]) {
				continue // glued to a letter, as in "hunter2"
			}
			digits := make([]byte, 0, 19)
			for j := i; j < len(groups); j++ {
				end := chain[0] + groups[j][1]
				digits = append(digits, s[chain[0]+groups[j][0]:end]...)
				if len(digits) > 19 {
					break
				}
				if end < len(s) && isWordByte(s[end]) {
					break
				}
				if plausibleCard(digits) {
					out = append(out, span{start, end, "CARD", prioCard})
					i = j
					break
				}
			}
		}
	}
	return out
}

func plausibleCard(d []byte) bool {
	n := len(d)
	if n != 13 && n != 15 && n != 16 && n != 19 {
		return false
	}
	p2 := string(d[:2])
	p4 := string(d[:4])
	switch {
	case d[0] == '4':
	case p2 >= "51" && p2 <= "55":
	case p4 >= "2221" && p4 <= "2720":
	case p2 == "34" || p2 == "37":
	case p4 == "6011" || p2 == "65":
	case p2 == "35":
	default:
		return false
	}
	return luhn(d)
}

func luhn(d []byte) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		v := int(d[i] - '0')
		if double {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		double = !double
	}
	return sum%10 == 0
}

// ---- email addresses --------------------------------------------------------------------------------

var emailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

func findEmail(s string) []span {
	var out []span
	for _, m := range emailRE.FindAllStringIndex(s, -1) {
		out = append(out, span{m[0], m[1], "EMAIL", prioEmail})
	}
	return out
}

// ---- IP addresses -----------------------------------------------------------------------------------

var ipv4RE = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)

func findIPv4(s string) []span {
	var out []span
	for _, m := range ipv4RE.FindAllStringIndex(s, -1) {
		a, b := m[0], m[1]
		if a > 0 && (isWordByte(s[a-1]) || (s[a-1] == '.' && a > 1 && isWordByte(s[a-2]))) {
			continue // part of a longer dotted token, such as 1.2.3.4.5 or v1.2.3.4
		}
		if b < len(s) && (isWordByte(s[b]) || (s[b] == '.' && b+1 < len(s) && isDigit(s[b+1]))) {
			continue
		}
		if !validIPv4(s[a:b]) || isBoringIPv4(s[a:b]) {
			continue
		}
		out = append(out, span{a, b, "IPV4", prioNet})
	}
	return out
}

func validIPv4(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n := 0
		for i := 0; i < len(p); i++ {
			n = n*10 + int(p[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// Loopback, "any" and broadcast say nothing about anybody's network.
func isBoringIPv4(v string) bool {
	return strings.HasPrefix(v, "127.") || v == "0.0.0.0" || v == "255.255.255.255"
}

var ipv6CandidateRE = regexp.MustCompile(`[0-9A-Fa-f:.]{3,}`)

var timeLikeRE = regexp.MustCompile(`^\d{1,2}(?::\d{2}){1,2}(?:\.\d+)?$`)

func findIPv6(s string) []span {
	var out []span
	for _, m := range ipv6CandidateRE.FindAllStringIndex(s, -1) {
		a, b := m[0], m[1]
		cand := s[a:b]
		for len(cand) > 0 && (cand[len(cand)-1] == '.' || (cand[len(cand)-1] == ':' && !strings.HasSuffix(cand, "::"))) {
			cand = cand[:len(cand)-1]
			b--
		}
		if strings.Count(cand, ":") < 2 || timeLikeRE.MatchString(cand) {
			continue
		}
		if a > 0 && (isWordByte(s[a-1]) || s[a-1] == ':') {
			continue
		}
		if b < len(s) && isWordByte(s[b]) {
			continue
		}
		ip := net.ParseIP(cand)
		if ip == nil || cand == "::" || cand == "::1" {
			continue
		}
		out = append(out, span{a, b, "IPV6", prioNet})
	}
	return out
}

var macRE = regexp.MustCompile(`[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}`)

func findMAC(s string) []span {
	var out []span
	for _, m := range macRE.FindAllStringIndex(s, -1) {
		a, b := m[0], m[1]
		if a > 0 && (isHex(s[a-1]) || s[a-1] == ':' || s[a-1] == '-') {
			continue
		}
		if b < len(s) && (isHex(s[b]) || ((s[b] == ':' || s[b] == '-') && b+1 < len(s) && isHex(s[b+1]))) {
			continue
		}
		v := strings.ToLower(s[a:b])
		if v == "ff:ff:ff:ff:ff:ff" || v == "00:00:00:00:00:00" || v == "ff-ff-ff-ff-ff-ff" || v == "00-00-00-00-00-00" {
			continue
		}
		out = append(out, span{a, b, "MAC", prioNet})
	}
	return out
}

// ---- user names -------------------------------------------------------------------------------------

// Each pattern has the user name in group 1.
var userREs = []*regexp.Regexp{
	regexp.MustCompile(`/home/([A-Za-z0-9._][A-Za-z0-9._-]*)`),
	regexp.MustCompile(`/Users/([A-Za-z0-9._][A-Za-z0-9._-]*)`),
	regexp.MustCompile(`(?i)[A-Z]:\\Users\\([A-Za-z0-9._][A-Za-z0-9._-]*)`),
	regexp.MustCompile(`(?i)\b(?:invalid user|failed password for|accepted \w+ for|session (?:opened|closed) for user|disconnected from (?:invalid |authenticating )?user)[ ]+(?:invalid user[ ]+)?([A-Za-z0-9._][A-Za-z0-9._-]*)`),
	regexp.MustCompile(`\b(?:USER|user|username|login)=([A-Za-z0-9._][A-Za-z0-9._-]*)`),
}

// Accounts every Linux machine has: naming them says nothing.
var systemUsers = map[string]bool{
	"root": true, "nobody": true, "daemon": true, "bin": true, "sys": true, "www-data": true,
	"sshd": true, "syslog": true, "messagebus": true, "_apt": true, "shared": true, "all": true,
	"from": true, "user": true, "for": true, "invalid": true,
}

func findUser(s string) []span {
	var out []span
	for _, re := range userREs {
		for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
			a, b := m[2], m[3]
			if a < 0 || b <= a {
				continue
			}
			name := s[a:b]
			if systemUsers[strings.ToLower(name)] || strings.HasPrefix(name, "systemd-") || isReference(name) {
				continue
			}
			out = append(out, span{a, b, "USER", prioUser})
		}
	}
	return out
}

// ---- host names -------------------------------------------------------------------------------------

var hostRE = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b`)

var privateTLDs = setOf("local", "internal", "lan", "corp", "intra", "intranet", "home", "localdomain", "lab", "private")

var commonTLDs = setOf("com", "net", "org", "io", "cloud", "ai", "co", "us", "uk", "de", "fr", "nl", "tr", "ru", "cn", "jp",
	"info", "biz", "edu", "gov", "mil", "eu", "tv", "xyz", "online", "site", "tech", "se", "fi", "dk", "es", "pl", "ch",
	"ca", "au", "br", "kr", "sg", "hk", "nz", "za")

// File extensions that look like a top-level domain.
var fileExtensions = setOf("go", "py", "js", "ts", "json", "yml", "yaml", "toml", "conf", "cfg", "ini", "log", "txt", "md",
	"service", "socket", "target", "timer", "mount", "sh", "bash", "c", "h", "cc", "cpp", "hpp", "so", "ko", "a", "o", "rs",
	"java", "class", "jar", "xml", "html", "css", "png", "jpg", "jpeg", "gif", "svg", "pdf", "zip", "gz", "tar", "tgz",
	"deb", "rpm", "pyc", "lock", "sum", "mod", "env", "key", "pem", "crt", "csr", "bak", "tmp", "swp", "orig", "rej",
	"patch", "diff", "sql", "csv", "tsv", "rb", "php", "pl", "lua", "scala", "kt", "swift", "cs", "vb", "bat", "ps")

// Public sites whose names say nothing about the user.
var publicDomains = []string{
	"github.com", "githubusercontent.com", "githubassets.com", "gitlab.com", "pypi.org", "pythonhosted.org", "python.org",
	"ubuntu.com", "debian.org", "canonical.com", "docker.io", "docker.com", "google.com", "googleapis.com", "golang.org",
	"go.dev", "npmjs.org", "npmjs.com", "kernel.org", "apache.org", "mozilla.org", "wikipedia.org", "readthedocs.io",
	"stackoverflow.com", "microsoft.com", "amazonaws.com", "cloudflare.com", "hashicorp.com", "terraform.io", "anthropic.com",
	"rust-lang.org", "crates.io", "rubygems.org", "nodejs.org", "w3.org", "ietf.org", "example.com", "example.org", "example.net",
}

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func findHost(s string) []span {
	var out []span
	for _, m := range hostRE.FindAllStringIndex(s, -1) {
		a, b := m[0], m[1]
		name := strings.ToLower(s[a:b])
		if a > 0 && isWordByte(s[a-1]) {
			continue // the tail of some longer word
		}
		labels := strings.Split(name, ".")
		tld := labels[len(labels)-1]
		switch {
		case fileExtensions[tld]:
			continue
		case privateTLDs[tld]:
		case commonTLDs[tld]:
		default:
			continue
		}
		if isPublicDomain(name) {
			continue
		}
		out = append(out, span{a, b, "HOST", prioHost})
	}
	return out
}

func isPublicDomain(name string) bool {
	for _, d := range publicDomains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}
