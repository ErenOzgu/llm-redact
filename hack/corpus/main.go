// Command corpus writes a set of realistic files full of FAKE secrets, for hack/leakcheck.sh.
//
// Nothing here is a real credential. Every value is made up at run time from a fixed seed, and no
// complete token appears in the source (a secret scanner would rightly complain about one), which
// is also why the files are generated instead of being committed.
//
//	go run ./hack/corpus DIR
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
)

var rng = mrand.New(mrand.NewSource(20261017))

func pick(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

const (
	alnum  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	lower  = "abcdefghijklmnopqrstuvwxyz0123456789"
	base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b64url = alnum + "-_"
	digits = "0123456789"
)

func awsKeyID() string    { return "AK" + "IA" + pick(base32, 16) }
func awsSecret() string   { return pick(alnum+"+/", 40) }
func githubToken() string { return "gh" + "p_" + pick(alnum, 36) }
func slackToken() string {
	return "xo" + "xb-" + pick(digits, 12) + "-" + pick(digits, 13) + "-" + pick(alnum, 24)
}
func googleAPIKey() string { return "AI" + "za" + pick(b64url, 35) }
func stripeKey() string    { return "sk_" + "live_" + pick(alnum, 24) }
func npmToken() string     { return "npm" + "_" + pick(lower, 36) }
func sendgridKey() string  { return "SG" + "." + pick(b64url, 22) + "." + pick(b64url, 43) }
func jwt() string {
	return "eyJ" + pick(b64url, 34) + ".eyJ" + pick(b64url, 60) + "." + pick(b64url, 43)
}
func ip() string {
	return fmt.Sprintf("%d.%d.%d.%d", 10+rng.Intn(3), rng.Intn(255), rng.Intn(255), 1+rng.Intn(253))
}
func host() string { return pick(lower, 5) + fmt.Sprintf("%02d.prod.corp", rng.Intn(40)) }
func email() string {
	return pick(lower, 6) + "." + pick(lower, 7) + "@" + pick(lower, 8) + ".example.com.tr"
}
func password() string { return pick(alnum, 6) + "-" + pick(alnum, 6) + "!" + pick(digits, 2) }

func write(dir, name, content string) {
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func pemBlock(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: corpus DIR")
		os.Exit(2)
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// An application log.
	log := ""
	for i := 0; i < 40; i++ {
		switch i % 8 {
		case 0:
			log += fmt.Sprintf("2026-10-17T10:%02d:11Z sshd[%d]: Failed password for invalid user %s from %s port %d ssh2\n", i, 1000+i, pick(lower, 6), ip(), 30000+i)
		case 1:
			log += fmt.Sprintf("2026-10-17T10:%02d:12Z api: POST /v1/login 401 user=%s@%s client=%s\n", i, pick(lower, 5), "corp.example.tr", ip())
		case 2:
			log += fmt.Sprintf("2026-10-17T10:%02d:13Z api: calling billing with Authorization: Bearer %s\n", i, jwt())
		case 3:
			log += fmt.Sprintf("2026-10-17T10:%02d:14Z worker: connect to %s (%s) timed out after 30s\n", i, host(), ip())
		case 4:
			log += fmt.Sprintf("2026-10-17T10:%02d:15Z deploy: using key %s id %s\n", i, awsSecret(), awsKeyID())
		case 5:
			log += fmt.Sprintf("2026-10-17T10:%02d:16Z notify: sent to %s via %s\n", i, email(), sendgridKey())
		case 6:
			log += fmt.Sprintf("2026-10-17T10:%02d:17Z git: fetch with %s failed\n", i, githubToken())
		default:
			log += fmt.Sprintf("2026-10-17T10:%02d:18Z net: link %s up, peer %s\n", i, "52:54:00:"+pick("0123456789abcdef", 2)+":"+pick("0123456789abcdef", 2)+":"+pick("0123456789abcdef", 2), ip())
		}
	}
	write(dir, "app.log", log)

	// A dotenv file.
	write(dir, ".env", fmt.Sprintf(`NODE_ENV=production
DATABASE_URL=postgres://app:%s@%s:5432/orders
AWS_ACCESS_KEY_ID=%s
AWS_SECRET_ACCESS_KEY=%s
STRIPE_SECRET_KEY=%s
SENDGRID_API_KEY=%s
NPM_TOKEN=%s
SLACK_BOT_TOKEN=%s
GOOGLE_API_KEY=%s
JWT_SECRET=%s
`, password(), host(), awsKeyID(), awsSecret(), stripeKey(), sendgridKey(), npmToken(), slackToken(), googleAPIKey(), pick(alnum, 48)))

	// A YAML config.
	write(dir, "config.yaml", fmt.Sprintf(`server:
  listen: %s:8443
  admin_email: %s
database:
  host: %s
  user: app
  password: %s
integrations:
  slack:
    token: %s
  github:
    api_token: %s
`, ip(), email(), host(), password(), slackToken(), githubToken()))

	// A deploy script.
	write(dir, "deploy.sh", fmt.Sprintf(`#!/bin/sh
set -e
export AWS_ACCESS_KEY_ID=%s
export AWS_SECRET_ACCESS_KEY=%s
curl -sS -H "Authorization: Bearer %s" https://%s/api/release
scp build.tar root@%s:/srv/app
echo "token=%s" >> /tmp/deploy.state
`, awsKeyID(), awsSecret(), githubToken(), host(), ip(), npmToken()))

	// A GCP service account key file, with a real (throw-away) RSA key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	saKey := pemBlock("PRIVATE KEY", der)
	write(dir, "service-account.json", fmt.Sprintf(`{
  "type": "service_account",
  "project_id": "orders-prod-%s",
  "private_key_id": "%s",
  "private_key": %q,
  "client_email": "deployer@orders-prod.iam.gserviceaccount.com"
}
`, pick(digits, 6), pick("0123456789abcdef", 40), saKey))

	// A bare ed25519 key and notes that mention things in prose.
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edKey)
	write(dir, "id_ed25519", pemBlock("PRIVATE KEY", edDER))

	write(dir, "notes.md", fmt.Sprintf(`# Incident notes

The page came in from %s at 03:12. Mail to %s bounced.
The service account password was reset to %s, then the Slack bot (%s) was rotated.
Console login: https://%s/login (user: %s, password: %s).
`, email(), email(), password(), slackToken(), host(), pick(lower, 6), password()))

	fmt.Println("wrote", dir)
}
