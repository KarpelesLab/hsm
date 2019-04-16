package yubihsm2

import "fmt"

type Error struct {
	Code ErrorCode
}

// Error formats a card error message into a human readable format
func (e *Error) Error() string {
	message := ""
	switch e.Code {
	case ErrorCodeOK:
		message = "OK"
	case ErrorCodeInvalidCommand:
		message = "Invalid command"
	case ErrorCodeInvalidData:
		message = "Invalid data"
	case ErrorCodeInvalidSession:
		message = "Invalid session"
	case ErrorCodeAuthFail:
		message = "Auth fail"
	case ErrorCodeSessionFull:
		message = "Session full"
	case ErrorCodeSessionFailed:
		message = "Session failed"
	case ErrorCodeStorageFailed:
		message = "Storage failed"
	case ErrorCodeWrongLength:
		message = "Wrong length"
	case ErrorCodeInvalidPermission:
		message = "Invalid permission"
	case ErrorCodeLogFull:
		message = "Log full"
	case ErrorCodeObjectNotFound:
		message = "Object not found"
	case ErrorCodeIDIllegal:
		message = "ID illegal"
	case ErrorCodeCommandUnexecuted:
		message = "Command unexecuted"
	default:
		message = "unknown"
	}

	return fmt.Sprintf("card responded with error: %s", message)
}
