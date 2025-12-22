package yubihsm2

import (
	"errors"
	"log"
	"sync"
	"time"
)

// SessionManager manages a pool of authenticated secure sessions with a YubiHSM2
type SessionManager struct {
	CommandHandler
	Plain CommandHandler

	session   *SecureChannel
	lock      sync.Mutex
	connector Connector
	authKeyID uint16
	authKey   AuthKey // Store derived key instead of password

	destroyed bool
	keepAlive *time.Timer
	swapping  bool
	swapLock  sync.Mutex // Protects swapping flag
}

var echoPayload = []byte("keepalive")

const pingInterval = 15 * time.Second

// NewSessionManager creates a new instance of the SessionManager with poolSize connections.
// Wait on channel Connected with a timeout to wait for active connections to be ready.
func NewSessionManager(connector Connector, authKeyID uint16, password string) (*SessionManager, error) {
	manager := &SessionManager{
		connector: connector,
		authKeyID: authKeyID,
		authKey:   deriveAuthKeyFromPwd(password), // Derive and store key, not password
		destroyed: false,
	}
	manager.CommandHandler = manager.SendEncryptedCommand
	manager.Plain = manager.SendCommand

	err := manager.swapSession()
	if err != nil {
		return nil, err
	}

	manager.keepAlive = time.NewTimer(pingInterval)
	go manager.pingRoutine()

	return manager, err
}

func (s *SessionManager) pingRoutine() {
	for range s.keepAlive.C {
		_, err := s.Echo(echoPayload)
		if err != nil {
			log.Printf("yubihsm2: failed to ping: %s", err)
		}

		s.keepAlive.Reset(pingInterval)
	}
}

func (s *SessionManager) swapSession() error {
	// Lock swapping process
	s.swapLock.Lock()
	s.swapping = true
	s.swapLock.Unlock()
	defer func() {
		s.swapLock.Lock()
		s.swapping = false
		s.swapLock.Unlock()
	}()

	newSession, err := NewSecureChannelWithKey(s.connector, s.authKeyID, s.authKey)
	if err != nil {
		return err
	}

	err = newSession.Authenticate()
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	// Close old session
	if s.session != nil {
		go s.session.Close()
	}

	// Replace primary session
	s.session = newSession

	return nil
}

func (s *SessionManager) checkSessionHealth() {
	s.swapLock.Lock()
	isSwapping := s.swapping
	s.swapLock.Unlock()

	if s.session.Counter >= MaxMessagesPerSession*0.9 && !isSwapping {
		go s.swapSession()
	}
}

// SendEncryptedCommand sends an encrypted & authenticated command to the HSM
// and returns the decrypted and parsed response.
func (s *SessionManager) SendEncryptedCommand(c *Command) (*WireResponse, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check session health after executing the command
	defer s.checkSessionHealth()

	if s.destroyed {
		return nil, errors.New("sessionmanager has already been destroyed")
	}
	if s.session == nil {
		return nil, errors.New("no session available")
	}

	// Reset keepalive since we are resetting the timeout by sending a command
	s.keepAlive.Reset(pingInterval)

	return s.session.SendEncryptedCommand(c)
}

// SendCommand sends an unauthenticated command to the HSM and returns the parsed response
func (s *SessionManager) SendCommand(c *Command) (*WireResponse, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.destroyed {
		return nil, errors.New("sessionmanager has already been destroyed")
	}
	if s.session == nil {
		return nil, errors.New("no session available")
	}

	return s.session.SendCommand(c)
}

// Destroy closes all connections in the pool.
// SessionManager instances can't be reused.
func (s *SessionManager) Destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.keepAlive.Stop()
	if s.session != nil {
		s.session.Close()
	}
	s.destroyed = true
}
