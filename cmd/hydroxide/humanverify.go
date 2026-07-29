package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/emersion/hydroxide/protonmail"
)

// ProtonMail's CAPTCHA challenge is an HTML page meant to be embedded in an
// iframe by ProtonMail's web clients: once the challenge is completed, the page
// sends the resulting token to its parent window with postMessage. It refuses
// to be embedded by anything other than ProtonMail's own domains, but when it's
// opened as a top-level document the message is delivered to the page itself.
//
// hydroxide serves the challenge from a local HTTP server with a small script
// injected, which listens for that message and sends the token back to us.

const captchaPath = "/core/v4/captcha"

// apiPathPrefix is the prefix of the paths we proxy through to the API itself.
// The challenge page loads the rest of its resources from the root of
// ProtonMail's API subdomain instead.
const apiPathPrefix = "/core/"

// tokenPath is where the injected script posts the completed token. It's
// prefixed so that it can't collide with a ProtonMail API path, which is
// proxied through to the API.
const tokenPath = "/hydroxide/token"

const injectedScript = `<script>
window.addEventListener("message", function(event) {
	if (!event.data || event.data.type !== "pm_captcha") {
		return;
	}
	var req = new XMLHttpRequest();
	req.open("POST", ` + "`" + tokenPath + "`" + `);
	req.send(event.data.token);
	document.body.textContent = "Verification complete, you can close this tab and go back to hydroxide.";
}, false);
</script>`

// humanVerifyServer serves the CAPTCHA challenge to a local web browser.
type humanVerifyServer struct {
	client *http.Client
	// rootURL is the ProtonMail API endpoint, assetsURL is the root of its API
	// subdomain, from which the challenge page loads its own resources
	rootURL   *url.URL
	assetsURL *url.URL
	token     string // the challenge token
	tokens    chan string
}

// apiSubdomainURL returns the root of the API subdomain for an API endpoint,
// e.g. https://mail-api.proton.me/ for https://mail.proton.me/api.
func apiSubdomainURL(rootURL *url.URL) *url.URL {
	u := *rootURL
	u.Path = ""
	u.RawQuery = ""

	name, rest, ok := strings.Cut(u.Hostname(), ".")
	if !ok || strings.HasSuffix(name, "-api") {
		return &u
	}

	host := name + "-api." + rest
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	u.Host = host
	return &u
}

func (s *humanVerifyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("human verification: %v %v", r.Method, r.URL.RequestURI())

	switch {
	case r.URL.Path == tokenPath:
		s.receiveToken(w, r)
	case r.URL.Path == "/favicon.ico":
		// Requested by the browser on its own. Don't forward it upstream,
		// which would reply with a confusing JSON error
		http.NotFound(w, r)
	case strings.HasPrefix(r.URL.Path, apiPathPrefix):
		s.proxy(w, r, s.rootURL)
	case r.URL.Path == "/":
		s.serveChallenge(w, r)
	default:
		// Resources loaded by the challenge page itself
		s.proxy(w, r, s.assetsURL)
	}
}

// upstreamURL returns the URL of p on base. Unlike path.Join, it preserves a
// trailing slash, which the challenge page's resources are sensitive to.
func upstreamURL(base *url.URL, p, rawQuery string) string {
	u := *base
	u.Path = strings.TrimSuffix(base.Path, "/") + p
	u.RawQuery = rawQuery
	return u.String()
}

func (s *humanVerifyServer) serveChallenge(w http.ResponseWriter, r *http.Request) {
	u := upstreamURL(s.rootURL, captchaPath, url.Values{
		"Token":             {s.token},
		"ForceWebMessaging": {"1"},
	}.Encode())

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("human verification: failed to fetch the challenge from %v: %v", u, resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// The challenge page has a Content-Security-Policy which forbids the
	// injected script, and it isn't sent back to the browser anyway
	if i := bytes.LastIndex(b, []byte("</body>")); i >= 0 {
		b = append(b[:i:i], append([]byte(injectedScript), b[i:]...)...)
	} else {
		b = append(b, []byte(injectedScript)...)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(resp.StatusCode)
	w.Write(b)
}

func (s *humanVerifyServer) receiveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "expected a POST request", http.StatusMethodNotAllowed)
		return
	}

	b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token := strings.TrimSpace(string(b))
	if token == "" {
		http.Error(w, "empty verification token", http.StatusBadRequest)
		return
	}

	select {
	case s.tokens <- token:
	default:
	}
	w.WriteHeader(http.StatusNoContent)
}

// proxy forwards a request from the challenge page to ProtonMail.
func (s *humanVerifyServer) proxy(w http.ResponseWriter, r *http.Request, base *url.URL) {
	u := upstreamURL(base, r.URL.Path, r.URL.RawQuery)

	req, err := http.NewRequestWithContext(r.Context(), r.Method, u, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for k, values := range r.Header {
		if k == "Host" || k == "Cookie" || k == "Origin" || k == "Referer" {
			continue
		}
		req.Header[k] = values
	}

	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, values := range resp.Header {
		switch k {
		case "Content-Security-Policy", "X-Frame-Options", "Set-Cookie":
			continue
		}
		w.Header()[k] = values
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// askHumanVerification asks the user to complete a human verification challenge
// in a web browser, then configures c to send the completed challenge along
// with subsequent requests.
func askHumanVerification(c *protonmail.Client, details *protonmail.HumanVerificationDetails) error {
	if !details.HasMethod(protonmail.HumanVerificationCaptcha) {
		return fmt.Errorf("ProtonMail requires human verification, but hydroxide only supports the CAPTCHA method (offered: %v)", strings.Join(details.Methods, ", "))
	}

	rootURL, err := url.Parse(c.RootURL)
	if err != nil {
		return fmt.Errorf("failed to parse API endpoint: %v", err)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	s := &humanVerifyServer{
		client:    httpClient,
		rootURL:   rootURL,
		assetsURL: apiSubdomainURL(rootURL),
		token:     details.Token,
		tokens:    make(chan string, 1),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to listen for human verification: %v", err)
	}
	defer ln.Close()

	go func() {
		if err := http.Serve(ln, s); err != nil {
			log.Printf("human verification server stopped: %v", err)
		}
	}()

	fmt.Fprintf(os.Stderr, "ProtonMail requires human verification.\n")
	fmt.Fprintf(os.Stderr, "Open the following URL in a web browser and complete the CAPTCHA:\n\n")
	fmt.Fprintf(os.Stderr, "\thttp://%v/\n\n", ln.Addr())
	fmt.Fprintf(os.Stderr, "Waiting for the CAPTCHA to be completed (paste a verification token and press Enter instead, if needed)...\n")

	// Let the user paste a token themselves, in case the browser can't reach
	// the local server
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return
		}
		if token := strings.TrimSpace(scanner.Text()); token != "" {
			select {
			case s.tokens <- token:
			default:
			}
		}
	}()

	token := <-s.tokens
	c.HumanVerification = &protonmail.HumanVerification{
		Token: token,
		Type:  protonmail.HumanVerificationCaptcha,
	}
	return nil
}
