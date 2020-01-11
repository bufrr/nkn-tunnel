package tunnel

import (
	"encoding/hex"
	"io"
	"log"
	"net"
	"strings"

	nknsdk "github.com/nknorg/nkn-sdk-go"
	"github.com/nknorg/nkn/common"
	"github.com/nknorg/nkn/crypto"
	"github.com/nknorg/nkn/vault"
)

type Tunnel struct {
	from        string
	to          string
	fromNKN     bool
	toNKN       bool
	listener    net.Listener
	multiClient *nknsdk.MultiClient
}

func NewTunnel(numClients int, seedHex, identifier, from, to string) (*Tunnel, error) {
	fromNKN := strings.ToLower(from) == "nkn"
	toNKN := !strings.Contains(to, ":")
	var m *nknsdk.MultiClient
	var err error

	if fromNKN || toNKN {
		var account *vault.Account
		var err error
		if len(seedHex) > 0 {
			seed, err := common.HexStringToBytes(seedHex)
			if err != nil {
				return nil, err
			}
			account, err = vault.NewAccountWithPrivatekey(crypto.GetPrivateKeyFromSeed(seed))
			if err != nil {
				return nil, err
			}
		} else {
			account, err = vault.NewAccount()
			if err != nil {
				return nil, err
			}
		}

		log.Println("Seed:", hex.EncodeToString(account.PrivateKey[:32]))

		m, err = nknsdk.NewMultiClient(account, identifier, numClients, false, nknsdk.ClientConfig{ConnectRetries: 1})
		if err != nil {
			return nil, err
		}
	}

	var listener net.Listener

	if fromNKN {
		listener = m
		from = m.Addr().String()
	} else {
		listener, err = net.Listen("tcp", from)
		if err != nil {
			return nil, err
		}
	}

	log.Println("Listening at", from)

	t := &Tunnel{
		from:        from,
		to:          to,
		fromNKN:     fromNKN,
		toNKN:       toNKN,
		listener:    listener,
		multiClient: m,
	}

	return t, nil
}

func (t *Tunnel) dial(addr string) (net.Conn, error) {
	if t.toNKN {
		return t.multiClient.Dial(addr)
	} else {
		return net.Dial("tcp", addr)
	}
}

func (t *Tunnel) Start() error {
	for {
		fromConn, err := t.listener.Accept()
		if err != nil {
			return err
		}

		go func(fromConn net.Conn) {
			toConn, err := t.dial(t.to)
			if err != nil {
				log.Println(err)
				return
			}

			pipe(fromConn, toConn)
		}(fromConn)
	}
}

func pipe(a, b net.Conn) {
	go func() {
		_, err := io.Copy(a, b)
		if err != nil {
			return
		}
	}()
	go func() {
		_, err := io.Copy(b, a)
		if err != nil {
			return
		}
	}()
}
