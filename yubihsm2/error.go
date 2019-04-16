package yubihsm2

import "fmt"

// Error formats a card error message into a human readable format
func (e ErrorCode) Error() string {
	message := ""
	switch e {
	case ErrOK:
		message = "OK"
	case ErrInvalidCommand:
		message = "Invalid command"
	case ErrInvalidData:
		message = "Invalid data"
	case ErrInvalidSession:
		message = "Invalid session"
	case ErrAuthFail:
		message = "Auth fail"
	case ErrSessionFull:
		message = "Session full"
	case ErrSessionFailed:
		message = "Session failed"
	case ErrStorageFailed:
		message = "Storage failed"
	case ErrWrongLength:
		message = "Wrong length"
	case ErrInvalidPermission:
		message = "Invalid permission"
	case ErrLogFull:
		message = "Log full"
	case ErrObjectNotFound:
		message = "Object not found"
	case ErrIDIllegal:
		message = "ID illegal"
	case ErrCommandUnexecuted:
		message = "Command unexecuted"
	default:
		message = "unknown"
	}

	return fmt.Sprintf("card responded with error: %s", message)
}
