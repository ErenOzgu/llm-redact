package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ErenOzgu/llm-redact/internal/redact"
)

const defaultModel = "claude-sonnet-5-5"

const systemPrompt = "Parts of the user's text were replaced by placeholders such as [[IPV4_1]], [[HOST_2]] or [[SECRET_1]]. " +
	"Each placeholder stands for one real value that you cannot see. " +
	"Use the placeholders exactly as written whenever you refer to those values, and never try to guess what is behind them."

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []message `json:"messages"`
}

type messagesResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func runAsk(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var c common
	var prompt, model string
	var maxTokens int
	var dryRun, stats bool
	fs := newFlagSet("ask", stderr)
	c.register(fs)
	fs.StringVar(&prompt, "prompt", "", "the question to ask about the text (required)")
	fs.StringVar(&model, "model", "", "model name (default $LLM_REDACT_MODEL, else "+defaultModel+")")
	fs.IntVar(&maxTokens, "max-tokens", 1500, "limit for the answer")
	fs.BoolVar(&dryRun, "dry-run", false, "print the request that would be sent (already masked) and stop")
	fs.BoolVar(&stats, "stats", false, "print how many values were masked, to stderr")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(prompt) == "" {
		return fail(stderr, errors.New("ask needs -prompt TEXT"))
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
	maskedPrompt, f1, err := r.Redact(prompt)
	if err != nil {
		return fail(stderr, err)
	}
	maskedText, f2, err := r.Redact(text)
	if err != nil {
		return fail(stderr, err)
	}
	if c.mapPath != "" {
		if err := m.Save(c.mapPath); err != nil {
			return fail(stderr, err)
		}
	}
	if stats {
		printStats(stderr, append(f1, f2...))
	}
	if model == "" {
		model = os.Getenv("LLM_REDACT_MODEL")
	}
	if model == "" {
		model = defaultModel
	}
	body, err := marshal(messagesRequest{
		Model: model, MaxTokens: maxTokens, System: systemPrompt,
		Messages: []message{{Role: "user", Content: maskedPrompt + "\n\n<input>\n" + maskedText + "\n</input>"}},
	})
	if err != nil {
		return fail(stderr, err)
	}
	if dryRun {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, body, "", "  ")
		fmt.Fprintln(stdout, pretty.String())
		return 0
	}
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return fail(stderr, errors.New("ANTHROPIC_API_KEY is not set (use -dry-run to see what would be sent)"))
	}
	base := strings.TrimRight(os.Getenv("ANTHROPIC_BASE_URL"), "/")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	answer, err := callMessages(base+"/v1/messages", key, body)
	if err != nil {
		fmt.Fprintf(stderr, "llm-redact: %v\n", err)
		return 1
	}
	restored, unknown := redact.Restore(answer, m)
	fmt.Fprintln(stdout, restored)
	if len(unknown) > 0 {
		fmt.Fprintf(stderr, "llm-redact: the answer contains placeholder(s) that are not in the table: %s\n", strings.Join(unknown, " "))
	}
	return 0
}

// marshal is json.Marshal without the escaping of <, > and &, so the dry-run output can be read.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func callMessages(url, key string, body []byte) (string, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := (&http.Client{Timeout: 180 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	var parsed messagesResponse
	jsonErr := json.Unmarshal(data, &parsed)
	if resp.StatusCode/100 != 2 {
		if jsonErr == nil && parsed.Error != nil {
			return "", fmt.Errorf("the API answered %d: %s: %s", resp.StatusCode, parsed.Error.Type, parsed.Error.Message)
		}
		return "", fmt.Errorf("the API answered %d", resp.StatusCode)
	}
	if jsonErr != nil {
		return "", fmt.Errorf("the API answer is not JSON: %w", jsonErr)
	}
	var out []string
	for _, block := range parsed.Content {
		if block.Type == "text" {
			out = append(out, block.Text)
		}
	}
	if len(out) == 0 {
		return "", errors.New("the API answer has no text")
	}
	return strings.Join(out, "\n"), nil
}
