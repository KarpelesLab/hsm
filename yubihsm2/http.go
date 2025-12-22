package yubihsm2

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Default HTTP client timeout for YubiHSM2 operations
const defaultHTTPTimeout = 30 * time.Second

// HTTPConnector implements the HTTP based connection with the YubiHSM2 connector
type HTTPConnector struct {
	URL    string
	client *http.Client
}

// NewHTTPConnector creates a new instance of HTTPConnector
func NewHTTPConnector(url string) *HTTPConnector {
	return &HTTPConnector{
		URL: url,
		client: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
	}
}

// Request encodes and executes a command on the HSM and returns the binary response
func (c *HTTPConnector) Request(command *Command) ([]byte, error) {
	requestData := command.Serialize()

	res, err := c.client.Post("http://"+c.URL+"/connector/api", "application/octet-stream", bytes.NewReader(requestData))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non OK status code %d", res.StatusCode)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// GetStatus requests the status of the HSM connector route /connector/status
func (c *HTTPConnector) GetStatus() (*StatusResponse, error) {
	res, err := c.client.Get("http://" + c.URL + "/connector/status")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	bodyString := string(data)
	pairs := strings.Split(bodyString, "\n")

	values := make(map[string]string)
	for _, pair := range pairs {
		pos := strings.Index(pair, "=")
		if pos == -1 {
			continue
		}
		values[pair[:pos]] = pair[pos+1:]
	}

	status := &StatusResponse{}
	status.Status = Status(values["status"])
	status.Serial = values["serial"]
	status.Version = values["version"]
	status.Pid = values["pid"]
	status.Address = values["address"]
	status.Port = values["port"]

	return status, nil
}
