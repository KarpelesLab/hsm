package yubihsm2

import (
	"strings"
	"testing"
)

func TestErrorCodeError(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		contains string
	}{
		{ErrOK, "OK"},
		{ErrInvalidCommand, "Invalid command"},
		{ErrInvalidData, "Invalid data"},
		{ErrInvalidSession, "Invalid session"},
		{ErrAuthFail, "Auth fail"},
		{ErrSessionFull, "Session full"},
		{ErrSessionFailed, "Session failed"},
		{ErrStorageFailed, "Storage failed"},
		{ErrWrongLength, "Wrong length"},
		{ErrInvalidPermission, "Invalid permission"},
		{ErrLogFull, "Log full"},
		{ErrObjectNotFound, "Object not found"},
		{ErrIDIllegal, "ID illegal"},
		{ErrCommandUnexecuted, "Command unexecuted"},
		{ErrorCode(0xAB), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			errMsg := tt.code.Error()
			if !strings.Contains(errMsg, tt.contains) {
				t.Errorf("Error() = %q, should contain %q", errMsg, tt.contains)
			}
			if !strings.Contains(errMsg, "card responded with error") {
				t.Errorf("Error() = %q, should contain standard prefix", errMsg)
			}
		})
	}
}

func TestErrorCodeImplementsError(t *testing.T) {
	var err error = ErrInvalidData
	if err.Error() == "" {
		t.Error("ErrorCode should implement error interface")
	}
}
