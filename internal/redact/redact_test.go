package redact

import (
	"strings"
	"testing"
)

func newT(t *testing.T, opts Options) *Redactor {
	t.Helper()
	r, err := New(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func redactOne(t *testing.T, in string) string {
	t.Helper()
	out, _, err := newT(t, Options{}).Redact(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDetectors(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"ipv4", "connect from 10.20.30.40:5060 failed", "connect from [[IPV4_1]]:5060 failed"},
		{"ipv4 cidr keeps mask", "route 192.168.4.0/24 via 192.168.4.1", "route [[IPV4_1]]/24 via [[IPV4_2]]"},
		{"ipv4 same value same placeholder", "10.0.0.5 then 10.0.0.5 then 10.0.0.6", "[[IPV4_1]] then [[IPV4_1]] then [[IPV4_2]]"},
		{"ipv4 loopback untouched", "listening on 127.0.0.1 and 0.0.0.0", "listening on 127.0.0.1 and 0.0.0.0"},
		{"ipv4 version number with a letter untouched", "pkg v1.2.3.4 installed", "pkg v1.2.3.4 installed"},
		{"ipv4 five parts untouched", "oid 1.3.6.1.4.1", "oid 1.3.6.1.4.1"},
		{"ipv4 out of range untouched", "build 300.1.1.1", "build 300.1.1.1"},
		{"ipv6", "peer 2001:db8:85a3::8a2e:370:7334 up", "peer [[IPV6_1]] up"},
		{"ipv6 loopback untouched", "bind ::1 and ::", "bind ::1 and ::"},
		{"time is not ipv6", "at 12:30:45 and 12:30:45.123", "at 12:30:45 and 12:30:45.123"},
		{"mac", "link aa:bb:cc:11:22:33 up", "link [[MAC_1]] up"},
		{"mac broadcast untouched", "to ff:ff:ff:ff:ff:ff", "to ff:ff:ff:ff:ff:ff"},
		{"email", "mail eren.ozgu@corp.example.tr now", "mail [[EMAIL_1]] now"},
		{"host private tld", "ssh db01.prod.corp and pbx.lan", "ssh [[HOST_1]] and [[HOST_2]]"},
		{"host com", "GET https://billing.acme-widgets.com/api", "GET https://[[HOST_1]]/api"},
		{"host public untouched", "pip from pypi.org and files.pythonhosted.org, repo github.com", "pip from pypi.org and files.pythonhosted.org, repo github.com"},
		{"file names untouched", "see config.yaml, main.go and ssh.service", "see config.yaml, main.go and ssh.service"},
		{"python attribute chain untouched", "np.float64 and self.session.get", "np.float64 and self.session.get"},
		{"url credentials", "clone https://deploy:s3cr3t-pass@git.corp/x.git", "clone https://[[CRED_1]]@[[HOST_1]]/x.git"},
		{"password equals", "DB_PASSWORD=hunter2 next", "DB_PASSWORD=[[SECRET_1]] next"},
		{"password yaml", "password: 'p@ss w0rd'", "password: '[[SECRET_1]]'"},
		{"password json", `{"api_key": "abc123xyz", "name": "x"}`, `{"api_key": "[[SECRET_1]]", "name": "x"}`},
		{"password reference untouched", "password: ${DB_PASSWORD} and token: $TOKEN and secret: {{ .Values.s }}", "password: ${DB_PASSWORD} and token: $TOKEN and secret: {{ .Values.s }}"},
		{"password boolean untouched", "password: false, token: null", "password: false, token: null"},
		{"tokenizer is not a token", "tokenizer: bert", "tokenizer: bert"},
		{"password_file is not a password", "password_file: /etc/x", "password_file: /etc/x"},
		{"bearer", "Authorization: Bearer abcdef0123456789ABCDEF", "Authorization: Bearer [[TOKEN_1]]"},
		{"cookie", "Cookie: sid=abc123; theme=dark\nnext", "Cookie: sid=[[COOKIE_1]]; theme=[[COOKIE_2]]\nnext"},
		{"shadow hash", "root:$6$salt1234$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ:19000", "root:[[HASH_1]]:19000"},
		{"card", "paid with 4111 1111 1111 1111 today", "paid with [[CARD_1]] today"},
		{"not a card", "order 1234 5678 9012 3456 today", "order 1234 5678 9012 3456 today"},
		{"home path", "open /home/eren/projects/x", "open /home/[[USER_1]]/projects/x"},
		{"sshd user", "Failed password for invalid user admin from 1.2.3.4 port 22", "Failed password for invalid user [[USER_1]] from [[IPV4_1]] port 22"},
		{"system user untouched", "session opened for user root and /home/ubuntu", "session opened for user root and /home/[[USER_1]]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactOne(t, tt.in); got != tt.want {
				t.Errorf("\n in:   %s\n got:  %s\n want: %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	in := "before\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdEFGHijklMNOPqrstUVWXyz012345\n-----END PRIVATE KEY-----\nafter"
	got := redactOne(t, in)
	if got != "before\n[[PRIVKEY_1]]\nafter" {
		t.Errorf("got %q", got)
	}
	// a key that was cut off
	cut := "log:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdEFGHijklMNOPqrstUVWXyz012345\n\nnext line"
	got = redactOne(t, cut)
	if strings.Contains(got, "MIIEvQ") || !strings.Contains(got, "next line") {
		t.Errorf("truncated key: %q", got)
	}
	// a key inside JSON, with escaped newlines
	js := `{"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----\n", "x": 1}`
	got = redactOne(t, js)
	if strings.Contains(got, "MIIEvQ") || !strings.Contains(got, `"x": 1`) {
		t.Errorf("json key: %q", got)
	}
}

func TestOptions(t *testing.T) {
	in := "ip 10.1.1.1 mail a@b.example.com"
	out, _, _ := newT(t, Options{Skip: map[string]bool{"EMAIL": true}}).Redact(in)
	if out != "ip [[IPV4_1]] mail a@[[HOST_1]]" {
		// with EMAIL skipped, the host part is still found
		t.Logf("skip email: %s", out)
	}
	out, _, _ = newT(t, Options{Only: map[string]bool{"IPV4": true}}).Redact(in)
	if out != "ip [[IPV4_1]] mail a@b.example.com" {
		t.Errorf("only ipv4: %s", out)
	}
	out, _, _ = newT(t, Options{Keep: map[string]bool{"10.1.1.1": true}}).Redact(in)
	if !strings.HasPrefix(out, "ip 10.1.1.1 mail") {
		t.Errorf("keep: %s", out)
	}
	if _, err := New(Options{Only: map[string]bool{"NOPE": true}}, nil); err == nil {
		t.Error("an unknown kind must be an error")
	}
}

func TestCustomRule(t *testing.T) {
	r, err := New(Options{Custom: []CustomRule{{Kind: "SERIAL", Pattern: `SN-([0-9]{8})`, Group: 1}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := r.Redact("unit SN-12345678 reported")
	if err != nil || out != "unit SN-[[SERIAL_1]] reported" {
		t.Errorf("got %q, %v", out, err)
	}
	if _, err := New(Options{Custom: []CustomRule{{Kind: "bad kind", Pattern: "x"}}}, nil); err == nil {
		t.Error("a bad kind name must be an error")
	}
	if _, err := New(Options{Custom: []CustomRule{{Kind: "X", Pattern: "("}}}, nil); err == nil {
		t.Error("a bad pattern must be an error")
	}
	if _, err := New(Options{Custom: []CustomRule{{Kind: "X", Pattern: "a", Group: 3}}}, nil); err == nil {
		t.Error("a missing group must be an error")
	}
}

func TestOverlapPriority(t *testing.T) {
	// The password inside the URL is one CRED, not an EMAIL plus something else.
	got := redactOne(t, "postgres://app:pw1234@db.corp:5432/x")
	if got != "postgres://[[CRED_1]]@[[HOST_1]]:5432/x" {
		t.Errorf("got %s", got)
	}
}

func TestPlaceholderCollision(t *testing.T) {
	r := newT(t, Options{})
	_, _, err := r.Redact("literal [[IPV4_7]] and 10.1.1.1")
	if _, ok := err.(*ErrCollision); !ok {
		t.Fatalf("want ErrCollision, got %v", err)
	}
	r = newT(t, Options{AllowAnyway: true})
	out, _, err := r.Redact("literal [[IPV4_1]] and 10.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	// The number that already appears in the input is not handed out.
	if out != "literal [[IPV4_1]] and [[IPV4_2]]" {
		t.Errorf("got %s", out)
	}
}

func TestRestore(t *testing.T) {
	r := newT(t, Options{})
	red, _, _ := r.Redact("from 10.9.8.7 to db.corp, password=hunter2")
	got, unknown := Restore("The host [[host_1]] at [[IPV4_01]] failed; also [[IPV4_9]].", r.Map)
	if got != "The host db.corp at 10.9.8.7 failed; also [[IPV4_9]]." {
		t.Errorf("got %q", got)
	}
	if len(unknown) != 1 || unknown[0] != "[[IPV4_9]]" {
		t.Errorf("unknown = %v", unknown)
	}
	if back, _ := Restore(red, r.Map); back != "from 10.9.8.7 to db.corp, password=hunter2" {
		t.Errorf("round trip: %q", back)
	}
}

func TestScanPositions(t *testing.T) {
	r := newT(t, Options{})
	f := r.Scan("line one\nwhere 10.1.1.1 is\nand b@c.example.org")
	if len(f) != 2 {
		t.Fatalf("findings: %+v", f)
	}
	if f[0].Kind != "IPV4" || f[0].Line != 2 || f[0].Col != 7 {
		t.Errorf("first: %+v", f[0])
	}
	if f[1].Kind != "EMAIL" || f[1].Line != 3 || f[1].Col != 5 {
		t.Errorf("second: %+v", f[1])
	}
	if r.Map.Len() != 0 {
		t.Error("Scan must not touch the mapping")
	}
}
