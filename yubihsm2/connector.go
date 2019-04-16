package yubihsm2

// Connector implements a simple request interface with a YubiHSM2
type Connector interface {
	// Request executes a command on the HSM and returns the binary response
	Request(command *CommandMessage) ([]byte, error)
	// GetStatus requests the status of the HSM connector (not working for direct USB)
	GetStatus() (*StatusResponse, error)
}

// Status represents a status state of the HSM
type Status string

// StatusResponse is the response to the GetStatus command containing information about the connector and HSM
type StatusResponse struct {
	Status  Status
	Serial  string
	Version string
	Pid     string
	Address string
	Port    string
}
