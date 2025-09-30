//go:build go1.24

package terasu

import (
	"context"
	"crypto"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"hash"
	"io"
	"unsafe"
)

//go:linkname defaultConfig crypto/tls.defaultConfig
func defaultConfig() *tls.Config

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

type clientHelloMsg struct {
	original                         []byte
	vers                             uint16
	random                           []byte
	sessionId                        []byte
	cipherSuites                     []uint16
	compressionMethods               []uint8
	serverName                       string
	ocspStapling                     bool
	supportedCurves                  []tls.CurveID
	supportedPoints                  []uint8
	ticketSupported                  bool
	sessionTicket                    []uint8
	supportedSignatureAlgorithms     []tls.SignatureScheme
	supportedSignatureAlgorithmsCert []tls.SignatureScheme
	secureRenegotiationSupported     bool
	secureRenegotiation              []byte
	extendedMasterSecret             bool
	alpnProtocols                    []string
	scts                             bool
	supportedVersions                []uint16
	cookie                           []byte
	keyShares                        []byte
	earlyData                        bool
	pskModes                         []uint8
	pskIdentities                    []pskIdentity
	pskBinders                       [][]byte
	quicTransportParameters          []byte
	encryptedClientHello             []byte
	// extensions are only populated on the server-side of a handshake
	extensions []uint16
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

//go:linkname clone crypto/tls.(*clientHelloMsg).clone
func clone(m *clientHelloMsg) *clientHelloMsg

func (m *clientHelloMsg) clone() *clientHelloMsg {
	return clone(m)
}

type keySharePrivateKeys struct {
	curveID tls.CurveID
	ecdhe   *ecdh.PrivateKey
	mlkem   *mlkem.DecapsulationKey768
}

type echCipher struct {
	KDFID  uint16
	AEADID uint16
}

type echExtension struct {
	Type uint16
	Data []byte
}

type echConfig struct {
	raw []byte

	Version uint16
	Length  uint16

	ConfigID             uint8
	KemID                uint16
	PublicKey            []byte
	SymmetricCipherSuite []echCipher

	MaxNameLength uint8
	PublicName    []byte
	Extensions    []echExtension
}

type uint128 struct {
	hi, lo uint64
}

type hpkecontext struct {
	aead cipher.AEAD

	sharedSecret []byte

	suiteID []byte

	key            []byte
	baseNonce      []byte
	exporterSecret []byte

	seqNum uint128
}

type hpkeSender struct {
	*hpkecontext
}

type echClientContext struct {
	config          *echConfig
	hpkeContext     *hpkeSender
	encapsulatedKey []byte
	innerHello      *clientHelloMsg
	innerTranscript hash.Hash
	kdfID           uint16
	aeadID          uint16
	echRejected     bool
	retryConfigs    []byte
}

//go:linkname makeClientHello crypto/tls.(*Conn).makeClientHello
func makeClientHello(c *_trsconn) (*clientHelloMsg, *keySharePrivateKeys, *echClientContext, error)

func (c *_trsconn) makeClientHello() (*clientHelloMsg, *keySharePrivateKeys, *echClientContext, error) {
	return makeClientHello(c)
}

// activeCert is a handle to a certificate held in the cache. Once there are
// no alive activeCerts for a given certificate, the certificate is removed
// from the cache by a finalizer.
type activeCert struct {
	cert *x509.Certificate
}

// A sessionState is a resumable session.
type sessionState struct {
	// Encoded as a SessionState (in the language of RFC 8446, Section 3).
	//
	//   enum { server(1), client(2) } SessionStateType;
	//
	//   opaque Certificate<1..2^24-1>;
	//
	//   Certificate CertificateChain<0..2^24-1>;
	//
	//   opaque Extra<0..2^24-1>;
	//
	//   struct {
	//       uint16 version;
	//       SessionStateType type;
	//       uint16 cipher_suite;
	//       uint64 created_at;
	//       opaque secret<1..2^8-1>;
	//       Extra extra<0..2^24-1>;
	//       uint8 ext_master_secret = { 0, 1 };
	//       uint8 early_data = { 0, 1 };
	//       CertificateEntry certificate_list<0..2^24-1>;
	//       CertificateChain verified_chains<0..2^24-1>; /* excluding leaf */
	//       select (SessionState.early_data) {
	//           case 0: Empty;
	//           case 1: opaque alpn<1..2^8-1>;
	//       };
	//       select (SessionState.type) {
	//           case server: Empty;
	//           case client: struct {
	//               select (SessionState.version) {
	//                   case VersionTLS10..VersionTLS12: Empty;
	//                   case VersionTLS13: struct {
	//                       uint64 use_by;
	//                       uint32 age_add;
	//                   };
	//               };
	//           };
	//       };
	//   } SessionState;
	//

	// Extra is ignored by crypto/tls, but is encoded by [SessionState.Bytes]
	// and parsed by [ParseSessionState].
	//
	// This allows [Config.UnwrapSession]/[Config.WrapSession] and
	// [ClientSessionCache] implementations to store and retrieve additional
	// data alongside this session.
	//
	// To allow different layers in a protocol stack to share this field,
	// applications must only append to it, not replace it, and must use entries
	// that can be recognized even if out of order (for example, by starting
	// with an id and version prefix).
	Extra [][]byte

	// EarlyData indicates whether the ticket can be used for 0-RTT in a QUIC
	// connection. The application may set this to false if it is true to
	// decline to offer 0-RTT even if supported.
	EarlyData bool

	version     uint16
	isClient    bool
	cipherSuite uint16
	// createdAt is the generation time of the secret on the sever (which for
	// TLS 1.0–1.2 might be earlier than the current session) and the time at
	// which the ticket was received on the client.
	createdAt         uint64 // seconds since UNIX epoch
	secret            []byte // master secret for TLS 1.2, or the PSK for TLS 1.3
	extMasterSecret   bool
	peerCertificates  []*x509.Certificate
	activeCertHandles []*activeCert
	ocspResponse      []byte
	scts              [][]byte
	verifiedChains    [][]*x509.Certificate
	alpnProtocol      string // only set if EarlyData is true

	// Client-side TLS 1.3-only fields.
	useBy  uint64 // seconds since UNIX epoch
	ageAdd uint32
	ticket []byte
}

type earlySecret struct {
	secret []byte
	hash   func() any
}

//go:linkname clientEarlyTrafficSecret crypto/internal/fips140/tls13.(*EarlySecret).ClientEarlyTrafficSecret
func clientEarlyTrafficSecret(s *earlySecret, transcript any) []byte

//go:linkname loadSession crypto/tls.(*Conn).loadSession
func loadSession(c *_trsconn, hello *clientHelloMsg) (
	session *sessionState, earlySecret *earlySecret, binderKey []byte, err error,
)

func (c *_trsconn) loadSession(hello *clientHelloMsg) (
	session *sessionState, earlySecret *earlySecret, binderKey []byte, err error,
) {
	return loadSession(c, hello)
}

//go:linkname clientSessionCacheKey crypto/tls.(*Conn).clientSessionCacheKey
func clientSessionCacheKey(c *_trsconn) string

func (c *_trsconn) clientSessionCacheKey() string {
	return clientSessionCacheKey(c)
}

// A cipherSuiteTLS13 defines only the pair of the AEAD algorithm and hash
// algorithm to be used with HKDF. See RFC 8446, Appendix B.4.
type cipherSuiteTLS13 struct {
	id     uint16
	keyLen int
	aead   func(key, fixedNonce []byte) any
	hash   crypto.Hash
}

//go:linkname deriveSecret crypto/tls.(*cipherSuiteTLS13).deriveSecret
func deriveSecret(c *cipherSuiteTLS13, secret []byte, label string, transcript hash.Hash) []byte

func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	return deriveSecret(c, secret, label, transcript)
}

//go:linkname cipherSuiteTLS13ByID crypto/tls.cipherSuiteTLS13ByID
func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
}

type transcriptHash interface {
	Write([]byte) (int, error)
}

//go:linkname transcriptMsg crypto/tls.transcriptMsg
func transcriptMsg(msg handshakeMessage, h transcriptHash) error

const clientEarlyTrafficLabel = "c e traffic"

//go:linkname quicSetWriteSecret crypto/tls.(*Conn).quicSetWriteSecret
func quicSetWriteSecret(c *_trsconn, level tls.QUICEncryptionLevel, suite uint16, secret []byte)

//go:linkname readHandshake crypto/tls.(*Conn).readHandshake
func readHandshake(c *_trsconn, transcript transcriptHash) (any, error)

func (c *_trsconn) readHandshake(transcript transcriptHash) (any, error) {
	return readHandshake(c, transcript)
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group tls.CurveID
	data  []byte
}

type serverHelloMsg struct {
	original                     []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	ocspStapling                 bool
	ticketSupported              bool
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	extendedMasterSecret         bool
	alpnProtocol                 string
	scts                         [][]byte
	supportedVersion             uint16
	serverShare                  keyShare
	selectedIdentityPresent      bool
	selectedIdentity             uint16
	supportedPoints              []uint8
	encryptedClientHello         []byte
	serverNameAck                bool

	// HelloRetryRequest extensions
	cookie        []byte
	selectedGroup tls.CurveID
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
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	keyShareKeys *keySharePrivateKeys

	session     *sessionState
	earlySecret *earlySecret
	binderKey   []byte

	certReq       unsafe.Pointer
	usingPSK      bool
	sentDummyCCS  bool
	suite         *cipherSuiteTLS13
	transcript    hash.Hash
	masterSecret  unsafe.Pointer
	trafficSecret []byte // client_application_traffic_secret_0

	echContext *echClientContext
}

//go:linkname handshake13 crypto/tls.(*clientHandshakeStateTLS13).handshake
func handshake13(hs *clientHandshakeStateTLS13) error

func (hs *clientHandshakeStateTLS13) handshake() error {
	return handshake13(hs)
}

type prfFunc func(secret []byte, label string, seed []byte, keyLen int) []byte

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
	prf     prfFunc
}

type clientHandshakeState struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        unsafe.Pointer
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

//go:linkname computeAndUpdateOuterECHExtension crypto/tls.computeAndUpdateOuterECHExtension
func computeAndUpdateOuterECHExtension(outer, inner *clientHelloMsg, ech *echClientContext, useKey bool) error

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

		hello, keyShareKeys, ech, err := c.makeClientHello()
		if err != nil {
			return err
		}
		c.serverName = hello.serverName

		session, earlySecret, binderKey, err := c.loadSession(hello)
		if err != nil {
			return err
		}
		if session != nil {
			defer func() {
				// If we got a handshake failure when resuming a session, throw away
				// the session ticket. See RFC 5077, Section 3.2.
				//
				// RFC 8446 makes no mention of dropping tickets on failure, but it
				// does require servers to abort on invalid binders, so we need to
				// delete tickets to recover from a corrupted PSK.
				if err != nil {
					if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
						c.config.ClientSessionCache.Put(cacheKey, nil)
					}
				}
			}()
		}

		if ech != nil {
			// Split hello into inner and outer
			ech.innerHello = hello.clone()

			// Overwrite the server name in the outer hello with the public facing
			// name.
			hello.serverName = string(ech.config.PublicName)
			// Generate a new random for the outer hello.
			hello.random = make([]byte, 32)
			_, err = io.ReadFull(tlsConfigRand(c.config), hello.random)
			if err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}

			// NOTE: we don't do PSK GREASE, in line with boringssl, it's meant to
			// work around _possibly_ broken middleboxes, but there is little-to-no
			// evidence that this is actually a problem.

			if err := computeAndUpdateOuterECHExtension(hello, ech.innerHello, ech, true); err != nil {
				return err
			}
		}

		c.serverName = hello.serverName

		if _, err := c.writeHandshakeRecord(hello, nil, firstFragmentLen); err != nil {
			return err
		}

		if hello.earlyData {
			suite := cipherSuiteTLS13ByID(session.cipherSuite)
			transcript := suite.hash.New()
			if err := transcriptMsg(hello, transcript); err != nil {
				return err
			}
			earlyTrafficSecret := clientEarlyTrafficSecret(earlySecret, transcript)
			quicSetWriteSecret(c, tls.QUICEncryptionLevelEarly, suite.id, earlyTrafficSecret)
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
				c:            cout,
				ctx:          ctx,
				serverHello:  serverHello,
				hello:        hello,
				keyShareKeys: keyShareKeys,
				session:      session,
				earlySecret:  earlySecret,
				binderKey:    binderKey,
				echContext:   ech,
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

		return nil
	}
}
