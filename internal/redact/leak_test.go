package redact

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Every secret below is assembled from pieces at run time, so that no complete token is in the
// source (secret scanners, including GitHub's push protection, would rightly complain about one).
func rep(unit string, n int) string { return strings.Repeat(unit, n)[:n] }

func tokenSecrets() map[string]string {
	return map[string]string{
		"aws access key id": "AK" + "IA" + "Z7Q2WMNB4XK5T9RD",
		"github pat":        "gh" + "p_" + rep("a1B2c3D4e5F6g7H8i9J0", 36),
		"github fine":       "github_" + "pat_" + rep("11AbCdEfG0hIjKlMnOpQrS_", 59),
		"gitlab":            "gl" + "pat-" + rep("x7Yz1Q2w3E4r5T6y7U8i", 24),
		"slack":             "xo" + "xb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
		"google api key":    "AI" + "za" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
		"google oauth":      "ya" + "29." + rep("a0AfB_byC5dEfGhIjKlMn", 60),
		"anthropic":         "sk-" + "ant-" + "api03-" + rep("Zk3Lm9Pq7Rt2Vw5Xy8Bc", 48),
		"openai":            "sk-" + "proj-" + rep("Qw3Er5Ty7Ui9Op1As2Df", 48),
		"stripe":            "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
		"npm":               "npm" + "_" + rep("aB3dE5gH7jK9mN1pQ3sT", 36),
		"pypi":              "pypi" + "-" + rep("AgEIcHlwaS5vcmc0Zk3Lm9Pq7Rt2", 70),
		"huggingface":       "hf" + "_" + rep("aBcDeFgHiJkLmNoPqRsT", 34),
		"sendgrid":          "SG" + "." + rep("aB3dE5gH7jK9mN1pQ3sT", 22) + "." + rep("xY7zA1bC3dE5fG7hI9jK", 43),
		"jwt":               "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"digitalocean":      "dop" + "_v1_" + rep("0123456789abcdef", 64),
		"docker":            "dckr" + "_pat_" + rep("aB3dE5gH7jK9mN1pQ3sT", 27),
	}
}

func TestTokensNeverSurvive(t *testing.T) {
	contexts := []string{
		"%s",
		"token seen: %s end",
		"export SOMETHING=%s",
		`{"value": "%s"}`,
		"https://h.example.net/path?key=%s&x=1",
		"Authorization: Bearer %s",
		"(%s)",
		"'%s'",
		"%s,",
		"line1\n%s\nline3",
	}
	for name, secret := range tokenSecrets() {
		for _, ctx := range contexts {
			in := fmt.Sprintf(ctx, secret)
			out, _, err := newT(t, Options{}).Redact(in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, secret) {
				t.Errorf("%s survived in context %q:\n%s", name, ctx, out)
			}
			// Not even a long piece of it may be left behind.
			if len(secret) > 24 && strings.Contains(out, secret[6:24]) {
				t.Errorf("%s left a fragment in context %q:\n%s", name, ctx, out)
			}
		}
	}
}

func TestKeyValueSecretsNeverSurvive(t *testing.T) {
	secrets := []string{
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYq7Xk2LmN9pRt",
		"hunter2",
		"p@ss:w0rd!",
		"correct-horse-battery-staple",
		"Zm9vOmJhcg==",
	}
	contexts := []string{
		"password=%s",
		"PASSWORD: %s",
		`"password": "%s"`,
		"db_password = %s",
		"aws_secret_access_key = %s",
		"client_secret=%s&grant_type=x",
		"--password=%s",
		"api_key: '%s'",
		"export API_TOKEN=%s",
		"Passwd = \"%s\"",
	}
	for _, secret := range secrets {
		for _, ctx := range contexts {
			in := fmt.Sprintf(ctx, secret)
			out, _, err := newT(t, Options{}).Redact(in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, secret) {
				t.Errorf("secret %q survived in %q: %s", secret, ctx, out)
			}
		}
	}
}

// pieces for random texts
var fragments = []string{
	"connect", "from", "failed", "to", "retry", "ok", "error:", "INFO", "[warn]", "[[x]]", "[", "]", "{", "}", ":", "=", ";",
	"10.20.30.40", "192.168.1.77/24", "2001:db8::17", "aa:bb:cc:11:22:33", "eren@corp.example.tr", "db01.prod.corp",
	"api.acme-widgets.com", "password=hunter2", "api_key: 'abc12345'", "Bearer abcdefghijklmnop0123", "/home/eren/x",
	"Failed password for invalid user mallory from 8.8.4.4", "4111 1111 1111 1111", "Cookie: a=b; c=d", "12:30:45", "v1.2.3.4",
	"127.0.0.1", "main.go", "pypi.org", "\n", "\n", "\t", " ", " ", " ", "é", "日本", "https://u:p4ss@git.corp/r.git",
}

func randomText(rng *rand.Rand) string {
	var b strings.Builder
	for i, n := 0, 1+rng.Intn(30); i < n; i++ {
		b.WriteString(fragments[rng.Intn(len(fragments))])
		// Fragments are always separated: gluing two of them together can create a new match
		// (such as a host name ending where a MAC address begins), which says nothing about real text.
		b.WriteByte(" \n "[rng.Intn(3)])
	}
	return b.String()
}

func TestRoundTripAndIdempotence(t *testing.T) {
	rng := rand.New(rand.NewSource(20261017))
	for i := 0; i < 3000; i++ {
		in := randomText(rng)
		r := newT(t, Options{})
		out, _, err := r.Redact(in)
		if err != nil {
			continue // the text itself contains a placeholder-like string
		}
		if back, unknown := Restore(out, r.Map); back != in || len(unknown) != 0 {
			t.Fatalf("round trip failed\n in:   %q\n out:  %q\n back: %q", in, out, back)
		}
		again, _, err := r.Redact(out)
		if err != nil || again != out {
			t.Fatalf("not idempotent\n out:   %q\n again: %q (%v)", out, again, err)
		}
	}
}

func TestSameValueSamePlaceholderAcrossTexts(t *testing.T) {
	r := newT(t, Options{})
	a, _, _ := r.Redact("from 10.1.1.1")
	b, _, _ := r.Redact("again 10.1.1.1 and 10.1.1.2")
	if a != "from [[IPV4_1]]" || b != "again [[IPV4_1]] and [[IPV4_2]]" {
		t.Errorf("a=%q b=%q", a, b)
	}
}

func FuzzRoundTrip(f *testing.F) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		f.Add(randomText(rng))
	}
	f.Add("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC")
	f.Add(`{"password": "a\"b", "k": [1,2]}`)
	f.Add("password=")
	f.Add("::::.....:::")
	f.Fuzz(func(t *testing.T, in string) {
		r, err := New(Options{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := r.Redact(in)
		if err != nil {
			return
		}
		if back, unknown := Restore(out, r.Map); back != in || len(unknown) != 0 {
			t.Fatalf("round trip failed\n in:   %q\n out:  %q\n back: %q", in, out, back)
		}
	})
}
