package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb, "test")
	return code, out.String(), errb.String()
}

const sample = "2026-10-17 sshd: Failed password for invalid user mallory from 203.0.113.9 port 4022\n" +
	"deploy: db=postgres://app:pw-9f8e7d@db01.prod.corp:5432/x password=hunter2 mail ops@corp.example.tr\n"

func TestRedactThenRestore(t *testing.T) {
	dir := t.TempDir()
	mp := filepath.Join(dir, "map.json")
	code, masked, _ := run(t, sample, "redact", "-map", mp)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, secret := range []string{"mallory", "203.0.113.9", "pw-9f8e7d", "db01.prod.corp", "hunter2", "ops@corp"} {
		if strings.Contains(masked, secret) {
			t.Errorf("%q survived:\n%s", secret, masked)
		}
	}
	st, err := os.Stat(mp)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("map file mode %v, want 0600", st.Mode().Perm())
	}
	code, back, _ := run(t, masked, "restore", "-map", mp)
	if code != 0 || back != sample {
		t.Errorf("restore: exit %d\n got:  %q\n want: %q", code, back, sample)
	}
}

func TestMapIsReusedAcrossRuns(t *testing.T) {
	mp := filepath.Join(t.TempDir(), "map.json")
	_, a, _ := run(t, "from 10.1.1.1\n", "redact", "-map", mp)
	_, b, _ := run(t, "again 10.1.1.1 and 10.1.1.2\n", "redact", "-map", mp)
	if a != "from [[IPV4_1]]\n" || b != "again [[IPV4_1]] and [[IPV4_2]]\n" {
		t.Errorf("a=%q b=%q", a, b)
	}
}

func TestRedactWithoutMapWarns(t *testing.T) {
	code, _, errs := run(t, "ip 10.1.1.1\n", "redact")
	if code != 0 || !strings.Contains(errs, "cannot be undone") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if _, _, errs := run(t, "ip 10.1.1.1\n", "redact", "-q"); errs != "" {
		t.Errorf("-q still printed %q", errs)
	}
}

func TestRestoreStrict(t *testing.T) {
	mp := filepath.Join(t.TempDir(), "map.json")
	run(t, "from 10.1.1.1\n", "redact", "-map", mp)
	code, out, errs := run(t, "[[IPV4_1]] and [[IPV4_9]]\n", "restore", "-map", mp)
	if code != 0 || out != "10.1.1.1 and [[IPV4_9]]\n" || !strings.Contains(errs, "IPV4_9") {
		t.Errorf("lenient: %d %q %q", code, out, errs)
	}
	if code, _, _ := run(t, "[[IPV4_9]]\n", "restore", "-strict", "-map", mp); code != 1 {
		t.Errorf("strict exit %d, want 1", code)
	}
	if code, _, _ := run(t, "x", "restore"); code != 2 {
		t.Errorf("missing -map exit %d, want 2", code)
	}
	if code, _, _ := run(t, "x", "restore", "-map", filepath.Join(t.TempDir(), "nope.json")); code != 2 {
		t.Errorf("missing map file exit %d, want 2", code)
	}
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	dirty := filepath.Join(dir, "dirty.log")
	clean := filepath.Join(dir, "clean.log")
	os.WriteFile(dirty, []byte("ok\nfrom 10.1.1.1 now\n"), 0o644)
	os.WriteFile(clean, []byte("nothing to see\n"), 0o644)

	code, out, _ := run(t, "", "check", clean)
	if code != 0 || out != "" {
		t.Errorf("clean: %d %q", code, out)
	}
	code, out, _ = run(t, "", "check", dirty, clean)
	if code != 1 || !strings.Contains(out, "dirty.log:2:6: IPV4 (8 bytes)") {
		t.Errorf("dirty: %d %q", code, out)
	}
	if strings.Contains(out, "10.1.1.1") {
		t.Error("check printed the value it found")
	}
	code, out, _ = run(t, "", "check", "-json", dirty)
	var parsed []checkFinding
	if err := json.Unmarshal([]byte(out), &parsed); err != nil || len(parsed) != 1 || parsed[0].Kind != "IPV4" || parsed[0].Line != 2 {
		t.Errorf("json: %v %q", err, out)
	}
	code, out, _ = run(t, "from 10.1.1.1\n", "check", "-json", "-only", "EMAIL")
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Errorf("-only EMAIL: %d %q", code, out)
	}
}

func TestOptionsAndRules(t *testing.T) {
	code, out, _ := run(t, "unit SN-12345678 at 10.1.1.1\n", "redact", "-q", "-rule", "SERIAL=SN-([0-9]{8})", "-skip", "IPV4")
	if code != 0 || out != "unit SN-[[SERIAL_1]] at 10.1.1.1\n" {
		t.Errorf("rule/skip: %d %q", code, out)
	}
	rules := filepath.Join(t.TempDir(), "rules.json")
	os.WriteFile(rules, []byte(`[{"kind":"BADGE","pattern":"EMP-[0-9]{5}","group":0}]`), 0o644)
	code, out, _ = run(t, "by EMP-00417\n", "redact", "-q", "-rules", rules)
	if code != 0 || out != "by [[BADGE_1]]\n" {
		t.Errorf("rules file: %d %q", code, out)
	}
	code, out, _ = run(t, "ip 10.1.1.1\n", "redact", "-q", "-keep", "10.1.1.1")
	if code != 0 || out != "ip 10.1.1.1\n" {
		t.Errorf("keep: %d %q", code, out)
	}
	if code, _, _ := run(t, "x", "redact", "-skip", "NOPE"); code != 2 {
		t.Errorf("unknown kind exit %d, want 2", code)
	}
	if code, _, _ := run(t, "x", "redact", "-rule", "nopattern"); code != 2 {
		t.Errorf("bad rule exit %d, want 2", code)
	}
}

func TestCollisionNeedsForce(t *testing.T) {
	code, _, errs := run(t, "literal [[IPV4_5]] and 10.1.1.1\n", "redact", "-q")
	if code != 2 || !strings.Contains(errs, "looks like a placeholder") {
		t.Errorf("exit %d, %q", code, errs)
	}
	if code, _, _ := run(t, "literal [[IPV4_5]] and 10.1.1.1\n", "redact", "-q", "-force"); code != 0 {
		t.Errorf("-force exit %d", code)
	}
}

func TestMaxBytes(t *testing.T) {
	if code, _, errs := run(t, strings.Repeat("a", 100), "redact", "-max-bytes", "10"); code != 2 || !strings.Contains(errs, "larger than") {
		t.Errorf("exit %d, %q", code, errs)
	}
}

func TestUsageAndList(t *testing.T) {
	if code, _, _ := run(t, ""); code != 2 {
		t.Errorf("no args exit %d, want 2", code)
	}
	if code, _, errs := run(t, "", "bogus"); code != 2 || !strings.Contains(errs, "unknown command") {
		t.Errorf("bogus: %d %q", code, errs)
	}
	code, out, _ := run(t, "", "list")
	if code != 0 || !strings.Contains(out, "PRIVKEY") || !strings.Contains(out, "HOST") {
		t.Errorf("list: %d %q", code, out)
	}
	if _, out, _ := run(t, "", "version"); strings.TrimSpace(out) != "llm-redact test" {
		t.Errorf("version: %q", out)
	}
}

// ---- ask, against a local server that speaks the shape of the Messages API ----------------------

func fakeAPI(t *testing.T, status int, reply func(req messagesRequest) string) (*httptest.Server, *[]byte) {
	t.Helper()
	var seen []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("x-api-key") != "test-key" || r.Header.Get("anthropic-version") != "2023-06-01" {
			w.WriteHeader(401)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"bad key"}}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		seen = body
		var req messagesRequest
		json.Unmarshal(body, &req)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		if status != 200 {
			io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error","message":"try later"}}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"type": "message", "role": "assistant",
			"content": []map[string]string{{"type": "text", "text": reply(req)}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestAskMasksTheRequestAndRestoresTheAnswer(t *testing.T) {
	srv, seen := fakeAPI(t, 200, func(req messagesRequest) string {
		// A model that answers about the placeholders it was given.
		return "Check [[HOST_1]]: the login from [[IPV4_1]] used a wrong password."
	})
	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	mp := filepath.Join(t.TempDir(), "map.json")
	code, out, errs := run(t, sample, "ask", "-map", mp, "-prompt", "What happened to db01.prod.corp?")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, secret := range []string{"mallory", "203.0.113.9", "pw-9f8e7d", "db01.prod.corp", "hunter2", "ops@corp"} {
		if strings.Contains(string(*seen), secret) {
			t.Errorf("%q was sent to the API:\n%s", secret, *seen)
		}
	}
	var req messagesRequest
	if err := json.Unmarshal(*seen, &req); err != nil {
		t.Fatal(err)
	}
	if req.Model != defaultModel || req.MaxTokens != 1500 || !strings.Contains(req.System, "placeholders") {
		t.Errorf("request: %+v", req)
	}
	if !strings.Contains(req.Messages[0].Content, "What happened to [[HOST_") {
		t.Errorf("the prompt itself must be masked too:\n%s", req.Messages[0].Content)
	}
	if !strings.Contains(out, "Check db01.prod.corp") || !strings.Contains(out, "login from 203.0.113.9") {
		t.Errorf("answer not restored: %q", out)
	}
}

func TestAskDryRunSendsNothing(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	code, out, _ := run(t, sample, "ask", "-dry-run", "-prompt", "why?")
	if code != 0 || !strings.Contains(out, `"max_tokens": 1500`) || strings.Contains(out, "hunter2") {
		t.Errorf("dry run: %d\n%s", code, out)
	}
}

func TestAskErrors(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	if code, _, errs := run(t, "x", "ask", "-prompt", "q"); code != 2 || !strings.Contains(errs, "ANTHROPIC_API_KEY") {
		t.Errorf("no key: %d %q", code, errs)
	}
	if code, _, errs := run(t, "x", "ask"); code != 2 || !strings.Contains(errs, "-prompt") {
		t.Errorf("no prompt: %d %q", code, errs)
	}
	srv, _ := fakeAPI(t, 529, nil)
	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	if code, _, errs := run(t, "x", "ask", "-prompt", "q"); code != 1 || !strings.Contains(errs, "overloaded_error") {
		t.Errorf("api error: %d %q", code, errs)
	}
	t.Setenv("ANTHROPIC_API_KEY", "wrong")
	if code, _, errs := run(t, "x", "ask", "-prompt", "q"); code != 1 || !strings.Contains(errs, "authentication_error") {
		t.Errorf("auth error: %d %q", code, errs)
	}
}
