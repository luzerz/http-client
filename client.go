package httpclient

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ------------------------------------------------------------------------------------------------------------
// Errors

// ClientErr struct
type ClientErr struct {
	Code    int
	Message string
}

func (e ClientErr) Error() string {
	return e.Message
}

// ----------------------------------------------------------------------------------------------------------------
// Implementation

// Get Send get request
func Get(url url.URL, contentType string, p map[string]string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	q := req.URL.Query()
	for k, v := range p {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := newHTTPClient().Do(req)

	err = parseErr(resp, err)
	if err != nil {
		return nil, err
	}

	var b []byte
	b, _, err = parseBody(resp)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Post Send post request
func Post(url url.URL, contentType string, body io.Reader, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("POST", url.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := newHTTPClient().Do(req)

	err = parseErr(resp, err)
	if err != nil {
		return nil, err
	}

	var b []byte
	b, _, err = parseBody(resp)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Put Send put request
func Put(url url.URL, contentType string, body io.Reader) error {
	req, err := http.NewRequest("PUT", url.String(), body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := newHTTPClient().Do(req)

	err = parseErr(resp, err)
	if err != nil {
		return err
	}

	_, _, err = parseBody(resp)
	if err != nil {
		return err
	}

	return nil
}

// Patch Send patch request
func Patch(url url.URL, contentType string, body io.Reader) error {
	req, err := http.NewRequest("PATCH", url.String(), body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := newHTTPClient().Do(req)

	err = parseErr(resp, err)
	if err != nil {
		return err
	}

	_, _, err = parseBody(resp)
	if err != nil {
		return err
	}

	return nil
}

// Delete Send delete request
func Delete(url url.URL, contentType string) error {
	req, err := http.NewRequest("DELETE", url.String(), nil)
	if err != nil {
		return err
	}

	resp, err := newHTTPClient().Do(req)

	err = parseErr(resp, err)
	if err != nil {
		return err
	}

	_, _, err = parseBody(resp)
	if err != nil {
		return err
	}

	return nil
}

// PostBasicAuth Send post request
func PostBasicAuth(url *url.URL, contentType string, body io.Reader, headers map[string]string, u string, p string) ([]byte, error) {
	auth := fmt.Sprintf("%s:%s", u, p)
	b64 := base64.StdEncoding.EncodeToString([]byte(auth))

	headers["Authorization"] = fmt.Sprintf("Basic %s", b64)

	return Post(*url, contentType, body, headers)
}

// ----------------------------------------------------------------------------------------------------------------
// Helpers

func newHTTPClient() *http.Client {
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}

func parseErr(resp *http.Response, err error) error {
	if resp == nil {
		err = ClientErr{
			Code:    500,
			Message: "Nil response",
		}

		return err
	}

	if err == nil && (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return nil
	}

	var target string
	var conditions []string
	if err != nil {
		target = "HTTPConnection"
		conditions = append(conditions, err.Error())
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, v, err := parseBody(resp)
		if err != nil {
			return err
		}
		logID := createErrorLog(v, resp.Request)

		target = "HTTPStatusCode"
		conditions = append(conditions, logID)
	}

	err = ClientErr{
		Code:    resp.StatusCode,
		Message: fmt.Sprintf("%s: %s", target, strings.Join(conditions, ", ")),
	}

	return err
}

func parseBody(resp *http.Response) ([]byte, interface{}, error) {
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if len(body) == 0 {
		return body, nil, nil
	}

	var ret interface{}
	switch resp.Header.Get("Content-Type") {
	case "application/json":
		err = json.Unmarshal(body, &ret)
		if err == nil {
			return body, ret, nil
		}
		break
	case "application/xml":
		err = xml.Unmarshal(body, &ret)
		if err != nil {
			return nil, nil, err
		}
		break
	default:
		ret = body
		break
	}

	return body, ret, nil
}

func createErrorLog(v interface{}, req *http.Request) string {
	logID := uuid.New().String()
	jsonVal, _ := json.Marshal(v)

	logger := log.NewLogfmtLogger(os.Stderr)
	logger.Log(
		"RequestURL", req.URL.String(),
		"logID", logID,
		"type", "RemoteServiceError",
		"error", string(jsonVal),
		"rawError", v,
	)

	return logID
}
