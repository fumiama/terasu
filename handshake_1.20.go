//go:build !go1.21

package terasu

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"hash"
	"time"
	"unsafe"
)

//go:linkname defaultConfig crypto/tls.defaultConfig
func defaultConfig() *tls.Config

type clientHelloMsg struct {
	raw                []byte
	vers               uint16
	random             []byte
	sessionId          []byte
	cipherSuites       []uint16
	compressionMethods []uint8
	serverName         string
}

//go:linkname marshal crypto/tls.(*clientHelloMsg).marshal
func marshal(m *clientHelloMsg) ([]byte, error)

func (m *clientHelloMsg) marshal() ([]byte, error) {
	return marshal(m)
}

//go:linkname unmarshal crypto/tls.(*clientHelloMsg).unmarshal
func unmarshal(m *clientHelloMsg, data []byte) bool

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	return unmarshal(m, data)
}

//go:linkname makeClientHello crypto/tls.(*Conn).makeClientHello
func makeClientHello(c *_trsconn) (*clientHelloMsg, *ecdh.PrivateKey, error)

func (c *_trsconn) makeClientHello() (*clientHelloMsg, *ecdh.PrivateKey, error) {
	return makeClientHello(c)
}

// ClientSessionState contains the state needed by clients to resume TLS
// sessions.
type sessionState struct {
	sessionTicket      []uint8               // Encrypted ticket used for session resumption with server
	vers               uint16                // TLS version negotiated for the session
	cipherSuite        uint16                // Ciphersuite negotiated for the session
	masterSecret       []byte                // Full handshake MasterSecret, or TLS 1.3 resumption_master_secret
	serverCertificates []*x509.Certificate   // Certificate chain presented by the server
	verifiedChains     [][]*x509.Certificate // Certificate chains we built for verification
	receivedAt         time.Time             // When the session ticket was received from the server
	ocspResponse       []byte                // Stapled OCSP response presented by the server
	scts               [][]byte              // SCTs presented by the server

	// TLS 1.3 fields.
	nonce  []byte    // Ticket nonce sent by the server, to derive PSK
	useBy  time.Time // Expiration of the ticket lifetime as set by the server
	ageAdd uint32    // Random obfuscation factor for sending the ticket age
}

//go:linkname loadSession crypto/tls.(*Conn).loadSession
func loadSession(c *_trsconn, hello *clientHelloMsg) (cacheKey string,
	session *sessionState, earlySecret, binderKey []byte, err error,
)

func (c *_trsconn) loadSession(hello *clientHelloMsg) (cacheKey string,
	session *sessionState, earlySecret, binderKey []byte, err error,
) {
	return loadSession(c, hello)
}

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
}

type transcriptHash interface {
	Write([]byte) (int, error)
}

//go:linkname transcriptMsg crypto/tls.transcriptMsg
func transcriptMsg(msg handshakeMessage, h transcriptHash) error

//go:linkname readHandshake crypto/tls.(*Conn).readHandshake
func readHandshake(c *_trsconn, transcript transcriptHash) (any, error)

func (c *_trsconn) readHandshake(transcript transcriptHash) (any, error) {
	return readHandshake(c, transcript)
}

type serverHelloMsg struct {
	raw    []byte
	vers   uint16
	random []byte
}

//go:linkname sendAlert crypto/tls.(*Conn).sendAlert
func sendAlert(c *_trsconn, err alert) error

func (c *_trsconn) sendAlert(err alert) error {
	return sendAlert(c, err)
}

//go:linkname unexpectedMessageError crypto/tls.unexpectedMessageError
func unexpectedMessageError(wanted, got any) error

const (
	alertUnexpectedMessage alert = 10
	alertIllegalParameter  alert = 47
)

//go:linkname pickTLSVersion crypto/tls.(*Conn).pickTLSVersion
func pickTLSVersion(c *_trsconn, serverHello *serverHelloMsg) error

func (c *_trsconn) pickTLSVersion(serverHello *serverHelloMsg) error {
	return pickTLSVersion(c, serverHello)
}

//go:linkname maxSupportedVersion crypto/tls.(*Config).maxSupportedVersion
func maxSupportedVersion(c *tls.Config, isClient bool) uint16

const roleClient = true

const (
	// downgradeCanaryTLS12 or downgradeCanaryTLS11 is embedded in the server
	// random as a downgrade protection if the server would be capable of
	// negotiating a higher version. See RFC 8446, Section 4.1.3.
	downgradeCanaryTLS12 = "DOWNGRD\x01"
	downgradeCanaryTLS11 = "DOWNGRD\x00"
)

type clientHandshakeStateTLS13 struct {
	c           *Conn
	ctx         context.Context
	serverHello *serverHelloMsg
	hello       *clientHelloMsg
	ecdheKey    *ecdh.PrivateKey

	session     *sessionState
	earlySecret []byte
	binderKey   []byte

	certReq       *uintptr
	usingPSK      bool
	sentDummyCCS  bool
	suite         *uintptr
	transcript    hash.Hash
	masterSecret  []byte
	trafficSecret []byte // client_application_traffic_secret_0
}

//go:linkname handshake13 crypto/tls.(*clientHandshakeStateTLS13).handshake
func handshake13(hs *clientHandshakeStateTLS13) error

func (hs *clientHandshakeStateTLS13) handshake() error {
	return handshake13(hs)
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	client hash.Hash
	server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	clientMD5 hash.Hash
	serverMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	buffer []byte

	version uint16
	prf     func(result, secret, label, seed []byte)
}

type clientHandshakeState struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *uintptr
	finishedHash finishedHash
	masterSecret []byte
	session      *sessionState // the session being resumed
	ticket       []byte        // a fresh ticket received during this handshake
}

//go:linkname handshake crypto/tls.(*clientHandshakeState).handshake
func handshake(hs *clientHandshakeState) error

func (hs *clientHandshakeState) handshake() error {
	return handshake(hs)
}

// writeHandshakeRecord writes a handshake message to the connection and updates
// the record layer state. If transcript is non-nil the marshalled message is
// written to it.
func (c *_trsconn) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash, firstFragmentLen uint8) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return 0, err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	return c.writeRecordLocked(recordTypeHandshake, firstFragmentLen, data)
}

func (cout *Conn) clientHandshake(firstFragmentLen uint8) func(context.Context) error {
	return func(ctx context.Context) (err error) {
		c := (*_trsconn)(unsafe.Pointer(cout))

		if c.config == nil {
			c.config = defaultConfig()
		}

		// This may be a renegotiation handshake, in which case some fields
		// need to be reset.
		c.didResume = false

		hello, ecdheKey, err := c.makeClientHello()
		if err != nil {
			return err
		}
		c.serverName = hello.serverName

		cacheKey, session, earlySecret, binderKey, err := c.loadSession(hello)
		if err != nil {
			return err
		}
		if cacheKey != "" && session != nil {
			defer func() {
				// If we got a handshake failure when resuming a session, throw away
				// the session ticket. See RFC 5077, Section 3.2.
				//
				// RFC 8446 makes no mention of dropping tickets on failure, but it
				// does require servers to abort on invalid binders, so we need to
				// delete tickets to recover from a corrupted PSK.
				if err != nil {
					c.config.ClientSessionCache.Put(cacheKey, nil)
				}
			}()
		}

		if _, err := c.writeHandshakeRecord(hello, nil, firstFragmentLen); err != nil {
			return err
		}

		// serverHelloMsg is not included in the transcript
		msg, err := c.readHandshake(nil)
		if err != nil {
			return err
		}

		var serverHello *serverHelloMsg
		if !isTypeEqual(msg, "*tls.serverHelloMsg") {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(serverHello, msg)
		}
		serverHello = (*serverHelloMsg)(*(*unsafe.Pointer)(
			unsafe.Add(unsafe.Pointer(&msg), unsafe.Sizeof(uintptr(0))),
		))

		if err := c.pickTLSVersion(serverHello); err != nil {
			return err
		}

		// If we are negotiating a protocol version that's lower than what we
		// support, check for the server downgrade canaries.
		// See RFC 8446, Section 4.1.3.
		maxVers := maxSupportedVersion(c.config, roleClient)
		tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
		tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
		if maxVers == tls.VersionTLS13 && c.vers <= tls.VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
			maxVers == tls.VersionTLS12 && c.vers <= tls.VersionTLS11 && tls11Downgrade {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox")
		}

		if c.vers == tls.VersionTLS13 {
			hs := &clientHandshakeStateTLS13{
				c:           cout,
				ctx:         ctx,
				serverHello: serverHello,
				hello:       hello,
				ecdheKey:    ecdheKey,
				session:     session,
				earlySecret: earlySecret,
				binderKey:   binderKey,
			}

			// In TLS 1.3, session tickets are delivered after the handshake.
			return hs.handshake()
		}

		hs := &clientHandshakeState{
			c:           cout,
			ctx:         ctx,
			serverHello: serverHello,
			hello:       hello,
			session:     session,
		}

		if err := hs.handshake(); err != nil {
			return err
		}

		// If we had a successful handshake and hs.session is different from
		// the one already cached - cache a new one.
		if cacheKey != "" && hs.session != nil && session != hs.session {
			c.config.ClientSessionCache.Put(cacheKey, (*tls.ClientSessionState)(unsafe.Pointer(hs.session)))
		}

		return nil
	}
}
