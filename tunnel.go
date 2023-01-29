package tunnel

import (
	"fmt"
	"github.com/nknorg/nkn/v2/crypto/ed25519"
	tpb "github.com/nknorg/tuna/pb"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	udpconn "github.com/nknorg/tuna/udp"

	"github.com/hashicorp/go-multierror"
	"github.com/nknorg/ncp-go"
	"github.com/nknorg/nkn-sdk-go"
	ts "github.com/nknorg/nkn-tuna-session"
	"github.com/nknorg/nkngomobile"
)

const (
	dataPrefix    = byte(0)
	pubkeyPrefix  = byte(1)
	sharedKeySize = 32
)

type nknDialer interface {
	Addr() net.Addr
	Dial(addr string) (net.Conn, error)
	DialUDP(remoteAddr string) (*udpconn.EncryptUDPConn, error)
	DialWithConfig(addr string, config *nkn.DialConfig) (*ncp.Session, error)
	DialUDPWithConfig(remoteAddr string, config *nkn.DialConfig) (*udpconn.EncryptUDPConn, error)
	Close() error
}

type nknListener interface {
	Listen(addrsRe *nkngomobile.StringArray) error
}

type multiClientDialer struct {
	c *nkn.MultiClient
}

func newMultiClientDialer(client *nkn.MultiClient) *multiClientDialer {
	return &multiClientDialer{c: client}
}

func (m *multiClientDialer) Addr() net.Addr {
	return m.c.Addr()
}

func (m *multiClientDialer) Dial(addr string) (net.Conn, error) {
	return m.c.Dial(addr)
}

func (m *multiClientDialer) DialUDP(remoteAddr string) (*udpconn.EncryptUDPConn, error) {
	return nil, nil
}

func (m *multiClientDialer) DialWithConfig(addr string, config *nkn.DialConfig) (*ncp.Session, error) {
	return m.c.DialWithConfig(addr, config)
}

func (m *multiClientDialer) DialUDPWithConfig(remoteAddr string, config *nkn.DialConfig) (*udpconn.EncryptUDPConn, error) {
	return nil, nil
}

func (m *multiClientDialer) Close() error {
	return m.c.Close()
}

// Tunnel is the tunnel client struct.
type Tunnel struct {
	from        string
	to          string
	fromNKN     bool
	toNKN       bool
	config      *Config
	dialer      nknDialer
	listeners   []net.Listener
	multiClient *nkn.MultiClient
	tsClient    *ts.TunaSessionClient
	fromUDPConn *udpconn.EncryptUDPConn
	toUDPConn   *udpconn.EncryptUDPConn

	lock     sync.RWMutex
	udpLock  sync.RWMutex
	isClosed bool
}

// NewTunnel creates a Tunnel client with given options.
func NewTunnel(account *nkn.Account, identifier, from, to string, tuna bool, config *Config) (*Tunnel, error) {
	config, err := MergedConfig(config)
	if err != nil {
		return nil, err
	}

	fromNKN := len(from) == 0 || strings.ToLower(from) == "nkn"
	toNKN := !strings.Contains(to, ":")
	var m *nkn.MultiClient
	var c *ts.TunaSessionClient
	var dialer nknDialer

	if fromNKN || toNKN {
		m, err = nkn.NewMultiClient(account, identifier, config.NumSubClients, config.OriginalClient, config.ClientConfig)
		if err != nil {
			return nil, err
		}

		<-m.OnConnect.C

		dialer = newMultiClientDialer(m)

		if tuna {
			wallet, err := nkn.NewWallet(account, config.WalletConfig)
			if err != nil {
				return nil, err
			}

			c, err = ts.NewTunaSessionClient(account, m, wallet, config.TunaSessionConfig)
			if err != nil {
				return nil, err
			}

			dialer = c
		}
	}

	listeners := make([]net.Listener, 0, 2)

	if fromNKN {
		if tuna {
			listeners = append(listeners, c)
			err = c.Listen(config.AcceptAddrs)
			if err != nil {
				return nil, err
			}
		}
		listeners = append(listeners, m)
		err = m.Listen(config.AcceptAddrs)
		if err != nil {
			return nil, err
		}
		from = m.Addr().String()
	} else {
		listener, err := net.Listen("tcp", from)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
	}

	log.Println("Listening at", from)

	t := &Tunnel{
		from:        from,
		to:          to,
		fromNKN:     fromNKN,
		toNKN:       toNKN,
		config:      config,
		dialer:      dialer,
		listeners:   listeners,
		multiClient: m,
		tsClient:    c,
	}

	return t, nil
}

// FromAddr returns the tunnel listening address.
func (t *Tunnel) FromAddr() string {
	return t.from
}

// ToAddr returns the tunnel dialing address.
func (t *Tunnel) ToAddr() string {
	return t.to
}

// Addr returns the tunnel NKN address.
func (t *Tunnel) Addr() net.Addr {
	return t.dialer.Addr()
}

// MultiClient returns the NKN multiclient that tunnel creates and uses.
func (t *Tunnel) MultiClient() *nkn.MultiClient {
	return t.multiClient
}

// TunaSessionClient returns the tuna session client that tunnel creates and
// uses. It is not nil only if tunnel is created with tuna == true.
func (t *Tunnel) TunaSessionClient() *ts.TunaSessionClient {
	return t.tsClient
}

// TunaPubAddrs returns the public node info of tuna listeners. Returns nil if
// there is no tuna listener.
func (t *Tunnel) TunaPubAddrs() *ts.PubAddrs {
	for _, listener := range t.listeners {
		if c, ok := listener.(*ts.TunaSessionClient); ok {
			return c.GetPubAddrs()
		}
	}
	return nil
}

// SetAcceptAddrs updates the accept address regex for incoming sessions.
// Tunnel will accept sessions from address that matches any of the given
// regular expressions. If addrsRe is nil, any address will be accepted. Each
// function call will overwrite previous accept addresses.
func (t *Tunnel) SetAcceptAddrs(addrsRe *nkngomobile.StringArray) error {
	if t.fromNKN {
		for _, listener := range t.listeners {
			err := listener.(nknListener).Listen(addrsRe)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Tunnel) dial(addr string) (net.Conn, error) {
	if t.toNKN {
		return t.dialer.DialWithConfig(addr, t.config.DialConfig)
	}
	var dialTimeout time.Duration
	if t.config.DialConfig != nil {
		dialTimeout = time.Duration(t.config.DialConfig.DialTimeout) * time.Millisecond
	}
	return net.DialTimeout("tcp", addr, dialTimeout)
}

func (t *Tunnel) dialUDP(addr string) (*udpconn.EncryptUDPConn, error) {
	if t.toNKN {
		conn, err := t.dialer.DialUDPWithConfig(addr, t.config.DialConfig)
		if err != nil {
			return nil, err
		}
		clientPubKey := t.tsClient.GetAccountPubKey()
		_, _, err = conn.WriteMsgUDP(append([]byte{pubkeyPrefix}, clientPubKey...), nil, nil)
		if err != nil {
			return nil, err
		}
		remotePublicKey, err := nkn.ClientAddrToPubKey(t.to)
		if err != nil {
			return nil, err
		}
		sharedKey, err := computeSharedKey(t.tsClient.GetAccountPrivKey(), remotePublicKey)
		if err != nil {
			return nil, err
		}

		remoteAddr := conn.RemoteUDPAddr()
		err = conn.AddCodec(remoteAddr, sharedKey, tpb.EncryptionAlgo_ENCRYPTION_XSALSA20_POLY1305, false)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	udpAddr := net.UDPAddr{IP: net.ParseIP(host), Port: port}
	conn, err := net.DialUDP("udp", nil, &udpAddr)
	if err != nil {
		return nil, err
	}
	return udpconn.NewEncryptUDPConn(conn), nil
}

// Start starts the tunnel and will return on error.
func (t *Tunnel) Start() error {
	errChan := make(chan error, 2)
	remoteAddr := new(net.UDPAddr)
	var port int
	var err error

	for _, listener := range t.listeners {
		go func(listener net.Listener) {
			for {
				fromConn, err := listener.Accept()
				if err != nil {
					errChan <- err
					return
				}

				log.Println("Accept from", fromConn.RemoteAddr())

				go func(fromConn net.Conn) {
					toConn, err := t.dial(t.to)
					if err != nil {
						log.Println(err)
						fromConn.Close()
						return
					}

					log.Println("Dial to", toConn.RemoteAddr())

					pipe(fromConn, toConn)
				}(fromConn)
			}
		}(listener)
	}

	if t.config.Udp {
		if t.fromNKN {
			if c, ok := t.listeners[0].(*ts.TunaSessionClient); ok {
				port = c.ServicePort()
			}
		} else {
			_, portStr, err := net.SplitHostPort(t.listeners[0].Addr().String())
			if err != nil {
				return err
			}
			port, _ = strconv.Atoi(portStr)
		}
		udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}

		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			log.Println("listen UDP err:", err)
			return err
		}
		fromUDPConn := udpconn.NewEncryptUDPConn(udpConn)

		toUDPConn, err := t.GetToUDPConn(true)
		if err != nil {
			log.Println("dialUDP err:", err)
		}

		if toUDPConn == nil {
			buf := make([]byte, udpconn.MaxUDPBufferSize)
			for {
				_, _, err := fromUDPConn.ReadFromUDP(buf[:])
				if err != nil {
					log.Println("read first udp package err:", err)
					continue
				}
				toUDPConn, err = t.GetToUDPConn(true)
				if err != nil {
					log.Println("dial UDP err:", err)
					continue
				}
				break
			}
		}

		go func() {
			buf := make([]byte, udpconn.MaxUDPBufferSize)
			msg := make([]byte, udpconn.MaxUDPBufferSize)
			var n int
			for {
				n, remoteAddr, err = fromUDPConn.ReadFromUDP(buf[:])
				if err != nil {
					log.Println("readFromUDP err:", err)
					continue
				}
				if t.fromNKN {
					if buf[0] == pubkeyPrefix {
						sharedKey, err := computeSharedKey(t.tsClient.GetAccountPrivKey(), buf[1:33])
						if err != nil {
							log.Println("compute sharedKey err:", err)
						}
						err = fromUDPConn.AddCodec(remoteAddr, sharedKey, tpb.EncryptionAlgo_ENCRYPTION_XSALSA20_POLY1305, false)
						if err != nil {
							log.Println("addCodec err:", err)
						}
						continue
					} else if buf[0] == dataPrefix {
						copy(msg, buf[1:n])
						n--
					} else {
						log.Println("invalid prefix")
						continue
					}
				}

				if t.toNKN {
					msg = append([]byte{dataPrefix}, buf...)
					n++
				}
				n, _, err = toUDPConn.WriteMsgUDP(msg[:n], nil, nil)
				if err != nil {
					log.Println("writeMsgUDP err:", err)
					toUDPConn, _ = t.GetToUDPConn(true)
					continue
				}
			}
		}()

		go func() {
			buf := make([]byte, udpconn.MaxUDPBufferSize)
			for {
				toUDPConn, err = t.GetToUDPConn(false)
				if err != nil {
					fmt.Println("get remote udp conn err:", err)
				}
				n, _, err := toUDPConn.ReadFromUDP(buf[:])
				if err != nil {
					log.Println("readFromUDP err:", err)
					toUDPConn, _ = t.GetToUDPConn(true)
					continue
				}
				n, _, err = fromUDPConn.WriteMsgUDP(buf[:n], nil, remoteAddr)
				if err != nil {
					log.Println("writeMsgUDP err:", err)
					continue
				}
			}
		}()
	}

	err = <-errChan

	if t.IsClosed() {
		return nil
	}

	t.Close()

	return err
}

// IsClosed returns whether the tunnel is closed.
func (t *Tunnel) IsClosed() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.isClosed
}

// Close will close the tunnel.
func (t *Tunnel) Close() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.isClosed {
		return nil
	}

	var errs error

	err := t.dialer.Close()
	if err != nil {
		errs = multierror.Append(errs, err)
	}

	for _, listener := range t.listeners {
		err = listener.Close()
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	t.isClosed = true

	return errs
}

func (t *Tunnel) SetFromUDPConn(conn *udpconn.EncryptUDPConn) {
	t.udpLock.Lock()
	defer t.udpLock.Unlock()
	t.fromUDPConn = conn
}

func (t *Tunnel) SetToUDPConn(conn *udpconn.EncryptUDPConn) {
	t.udpLock.Lock()
	defer t.udpLock.Unlock()
	t.toUDPConn = conn
}

func (t *Tunnel) GetFromUDPConn() *udpconn.EncryptUDPConn {
	t.udpLock.Lock()
	defer t.udpLock.Unlock()
	return t.fromUDPConn
}

func (t *Tunnel) GetToUDPConn(force bool) (*udpconn.EncryptUDPConn, error) {
	t.udpLock.Lock()
	defer t.udpLock.Unlock()
	if force {
		conn, err := t.dialUDP(t.to)
		if err != nil {
			return nil, err
		}
		t.toUDPConn = conn
	}
	return t.toUDPConn, nil
}

func pipe(a, b net.Conn) {
	go func() {
		io.Copy(a, b)
		a.Close()
	}()
	go func() {
		io.Copy(b, a)
		b.Close()
	}()
}

func computeSharedKey(privKey []byte, pubKey []byte) (*[sharedKeySize]byte, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key length is %d, expecting %d", len(pubKey), ed25519.PublicKeySize)
	}

	var pk [ed25519.PublicKeySize]byte
	copy(pk[:], pubKey)
	curve25519PublicKey, ok := ed25519.PublicKeyToCurve25519PublicKey(&pk)
	if !ok {
		return nil, fmt.Errorf("converting public key %x to curve25519 public key failed", pubKey)
	}

	var sk [ed25519.PrivateKeySize]byte
	copy(sk[:], privKey)
	curveSecretKey := ed25519.PrivateKeyToCurve25519PrivateKey(&sk)

	sharedKey := new([sharedKeySize]byte)
	box.Precompute(sharedKey, curve25519PublicKey, curveSecretKey)

	return sharedKey, nil
}
