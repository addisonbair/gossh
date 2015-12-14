package gossh

import (
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// PublicKeyFile satisfies the ssh.AuthMethod interface
// for authentication via Public Key
func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}

	return ssh.PublicKeys(key)
}

// ClientConfig ...
type ClientConfig struct {
	User   string
	Auth   ssh.AuthMethod
	Server string
	Port   int
}

// InitSessionManager ...
func InitSessionManager(c *ClientConfig) (*SessionManager, error) {
	sm := new(SessionManager)
	sm.clientConfig = c

	client, err := sm.initClient()
	if err != nil {
		return nil, err
	}

	sm.sshClient = client
	return sm, err
}

// SessionManager manages the state of ssh client sessions
// by reusing a TCP connection for multiple sessions
type SessionManager struct {
	sshClient    *ssh.Client
	clientConfig *ClientConfig
}

// Output in the style of ssh.Session.Output,
// Creates and closes a new session while returning output
func (sm *SessionManager) Output(cmd string) ([]byte, error) {
	session, err := sm.initSession()
	if err != nil {
		return nil,
			fmt.Errorf("Could not establish a session with server: %s", err)
	}
	output, err := session.Output(cmd)
	session.Close()
	return output, nil
}

func (sm *SessionManager) initSession() (*ssh.Session, error) {
	session, err := sm.sshClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("Failed to create session: %s", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		session.Close()
		return nil, fmt.Errorf("Request for pseudo terminal failed: %s", err)
	}

	return session, nil
}

func (sm *SessionManager) initClient() (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: sm.clientConfig.User,
		Auth: []ssh.AuthMethod{
			sm.clientConfig.Auth,
		},
	}
	hostString := fmt.Sprintf("%s:%d", sm.clientConfig.Server, sm.clientConfig.Port)

	client, err := ssh.Dial("tcp", hostString, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to dial: %s", err)
	}

	return client, nil
}
