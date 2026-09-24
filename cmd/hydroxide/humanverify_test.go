package main

import (
	"bufio"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

// withPipes swaps os.Stdin and os.Stderr for pipes and returns the stdin
// writer and a channel yielding the local verification URL printed to stderr.
func withPipes(t *testing.T) (*os.File, <-chan string) {
	t.Helper()
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin, oldStderr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = stdinR, stderrW
	t.Cleanup(func() {
		os.Stdin, os.Stderr = oldStdin, oldStderr
		stdinW.Close()
		stderrW.Close()
	})

	urls := make(chan string, 1)
	go func() {
		re := regexp.MustCompile(`http://127\.0\.0\.1:\d+/`)
		s := bufio.NewScanner(stderrR)
		for s.Scan() {
			if u := re.FindString(s.Text()); u != "" {
				urls <- u
			}
		}
	}()
	return stdinW, urls
}

func startVerification(t *testing.T) (*protonmail.Client, <-chan error) {
	t.Helper()
	c := &protonmail.Client{RootURL: "https://mail.proton.me/api", HTTPClient: http.DefaultClient}
	details := &protonmail.HumanVerificationDetails{Methods: []string{"captcha"}, Token: "challenge"}
	done := make(chan error, 1)
	go func() { done <- askHumanVerification(c, details) }()
	return c, done
}

// nextLine reads the line a later prompt (like the 2FA code) would get.
func nextLine(t *testing.T, stdinW *os.File, input string) string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(os.Stdin)
		s.Scan()
		got <- s.Text()
	}()
	time.Sleep(50 * time.Millisecond)
	stdinW.WriteString(input + "\n")
	select {
	case line := <-got:
		return line
	case <-time.After(2 * time.Second):
		t.Fatalf("next prompt never received %q: swallowed by the verification reader", input)
		return ""
	}
}

func TestBrowserTokenDoesNotSwallowNextPrompt(t *testing.T) {
	stdinW, urls := withPipes(t)
	c, done := startVerification(t)

	u := <-urls
	resp, err := http.Post(u+"hydroxide/token", "text/plain", strings.NewReader("browser-token"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case <-done:
		t.Fatal("returned before the stdin reader was released")
	case <-time.After(200 * time.Millisecond):
	}
	stdinW.WriteString("\n") // "press Enter to continue"
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not return after Enter")
	}
	if c.HumanVerification == nil || c.HumanVerification.Token != "browser-token" {
		t.Fatalf("token = %+v", c.HumanVerification)
	}
	if got := nextLine(t, stdinW, "123456"); got != "123456" {
		t.Fatalf("2FA prompt got %q", got)
	}
}

func TestPastedTokenDoesNotSwallowNextPrompt(t *testing.T) {
	stdinW, urls := withPipes(t)
	c, done := startVerification(t)

	<-urls
	stdinW.WriteString("pasted-token\n")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not return after pasting a token")
	}
	if c.HumanVerification == nil || c.HumanVerification.Token != "pasted-token" {
		t.Fatalf("token = %+v", c.HumanVerification)
	}
	if got := nextLine(t, stdinW, "654321"); got != "654321" {
		t.Fatalf("2FA prompt got %q", got)
	}
}
