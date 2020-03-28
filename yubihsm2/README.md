# YubiHSM2

[GoDoc](https://godoc.org/github.com/KarpelesLab/hsm/yubihsm2)

Code comes initally from: https://github.com/certusone/yubihsm-go (Apache 2.0 license)

# Details

YubiHSM2 is a minimal implementation of the securechannel and connector protocol of the YubiHSM2.

It also implements a simple SessionManager which keeps connections alive and swaps them if the maximum number of
messages is depleted.

Currently the following commands are implemented:

 * Reset
 * GenerateAsymmetricKey
 * SignDataEddsa
 * PutAsymmetricKey
 * GetPubKey
 * Echo
 * Authentication & Session related commands
 * And many more, see cmd.go

Implementing new commands is really easy. Please consult cmd.go.

Please submit a PR if you have implemented new commands.

## Example of usage

```
c := yubihsm2.NewHTTPConnector("localhost:12345")
sm, err := yubihsm2.NewSessionManager(c, 1, "password")
if err != nil {
	panic(err)
}

echoMessage := []byte("test")

res, err := sm.Echo(echoMessage)
if err != nil {
	panic(err)
}

if bytes.Equal(res, echoMessage) {
	println("successfully echoed data")
} else {
	panic(errors.New("echoed message did not equal requested message"))
}

```
