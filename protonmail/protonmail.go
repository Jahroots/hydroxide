// Package protonmail implements a ProtonMail API client.
package protonmail

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"log"
)

const Version = 3

const headerAPIVersion = "X-Pm-Apiversion"

type resp struct {
	Code int
	*RawAPIError
}

func (r *resp) Err() error {
	if err := r.RawAPIError; err != nil {
		return &APIError{
			Code:    r.Code,
			Message: err.Message,
			Details: err.Details,
		}
	}
	return nil
}

type maybeError interface {
	Err() error
}

type RawAPIError struct {
	Message string          `json:"Error"`
	Details json.RawMessage `json:"Details"`
}

type APIError struct {
	Code    int
	Message string
	Details json.RawMessage
}

func (err *APIError) Error() string {
	return fmt.Sprintf("[%v] %v", err.Code, err.Message)
}

// API error codes.
const (
	CodeHumanVerificationRequired = 9001
	CodeHumanVerificationInvalid  = 9002
)

// Human verification methods.
const (
	HumanVerificationCaptcha = "captcha"
)

// HumanVerificationDetails describes a human verification challenge the API
// wants the user to complete before it accepts the request.
type HumanVerificationDetails struct {
	Methods []string `json:"HumanVerificationMethods"`
	Token   string   `json:"HumanVerificationToken"`
}

// HasMethod returns true if the API offers the provided verification method.
func (details *HumanVerificationDetails) HasMethod(method string) bool {
	for _, m := range details.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// HumanVerificationDetails returns the human verification challenge attached to
// this error, if any.
func (err *APIError) HumanVerificationDetails() *HumanVerificationDetails {
	if err.Code != CodeHumanVerificationRequired || len(err.Details) == 0 {
		return nil
	}
	details := new(HumanVerificationDetails)
	if err := json.Unmarshal(err.Details, details); err != nil {
		return nil
	}
	if details.Token == "" {
		return nil
	}
	return details
}

// HumanVerificationDetailsFromError returns the human verification challenge
// attached to err, if err is an API error requesting human verification.
func HumanVerificationDetailsFromError(err error) *HumanVerificationDetails {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return nil
	}
	return apiErr.HumanVerificationDetails()
}

// HumanVerification is a completed human verification challenge. Note that its
// token is the one produced by completing the challenge, not the challenge
// token from HumanVerificationDetails.
type HumanVerification struct {
	Token string
	Type  string
}

type Timestamp int64

func (t Timestamp) Time() time.Time {
	return time.Unix(int64(t), 0)
}

// Client is a ProtonMail API client.
type Client struct {
	RootURL    string
	AppVersion string
	Debug      bool

	// HumanVerification, if non-nil, is sent along with each request to prove
	// that a human verification challenge has been completed.
	HumanVerification *HumanVerification

	HTTPClient *http.Client
	ReAuth     func() error

	uid         string
	accessToken string
	keyRing     openpgp.EntityList
}

func (c *Client) setRequestAuthorization(req *http.Request) {
	if c.uid != "" && c.accessToken != "" {
		req.Header.Set("X-Pm-Uid", c.uid)
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.RootURL+path, body)
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Printf(">> %v %v\n", req.Method, req.URL.Path)
	}

	req.Header.Set("X-Pm-Appversion", c.AppVersion)
	req.Header.Set(headerAPIVersion, strconv.Itoa(Version))
	if hv := c.HumanVerification; hv != nil {
		req.Header.Set("X-Pm-Human-Verification-Token", hv.Token)
		req.Header.Set("X-Pm-Human-Verification-Token-Type", hv.Type)
	}
	c.setRequestAuthorization(req)
	return req, nil
}

func (c *Client) newJSONRequest(method, path string, body interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}
	b := buf.Bytes()

	req, err := c.newRequest(method, path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Print(string(b))
	}

	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) {
		return ioutil.NopCloser(bytes.NewReader(b)), nil
	}
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return resp, err
	}

	// Check if access token has expired
	_, hasAuth := req.Header["Authorization"]
	canRetry := req.Body == nil || req.GetBody != nil
	if resp.StatusCode == http.StatusUnauthorized && hasAuth && c.ReAuth != nil && canRetry {
		resp.Body.Close()
		c.accessToken = ""
		if err := c.ReAuth(); err != nil {
			return resp, err
		}
		c.setRequestAuthorization(req) // Access token has changed
		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return resp, err
			}
			req.Body = body
		}
		return c.do(req)
	}

	return resp, nil
}

func (c *Client) doJSON(req *http.Request, respData interface{}) error {
	req.Header.Set("Accept", "application/json")

	if respData == nil {
		respData = new(resp)
	}

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
		return err
	}

	if c.Debug {
		log.Printf("<< %v %v", req.Method, req.URL.Path)
		log.Printf("%#v", respData)
	}

	if maybeError, ok := respData.(maybeError); ok {
		if err := maybeError.Err(); err != nil {
			log.Printf("request failed: %v %v: %v", req.Method, req.URL.String(), err)
			return err
		}
	}
	return nil
}
