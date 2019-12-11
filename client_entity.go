package dmsg

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/SkycoinProject/skycoin/src/util/logging"

	"github.com/SkycoinProject/dmsg/cipher"
	"github.com/SkycoinProject/dmsg/disc"
	"github.com/SkycoinProject/dmsg/netutil"
)

// Config configures a dmsg client entity.
type Config struct {
	MinSessions int
}

// DefaultConfig returns the default configuration for a dmsg client entity.
func DefaultConfig() *Config {
	return &Config{
		MinSessions: 1,
	}
}

// ClientEntity represents a dmsg client entity.
type ClientEntity struct {
	EntityCommon
	conf   *Config
	porter *netutil.Porter
	errCh  chan error
	done   chan struct{}
	once   sync.Once

	sesMx sync.Mutex
}

// NewClient creates a dmsg client entity.
func NewClient(pk cipher.PubKey, sk cipher.SecKey, dc disc.APIClient, conf *Config) *ClientEntity {
	if conf == nil {
		conf = DefaultConfig()
	}

	c := new(ClientEntity)
	c.conf = conf
	c.porter = netutil.NewPorter(netutil.PorterMinEphemeral)
	c.errCh = make(chan error, 10)
	c.done = make(chan struct{})

	c.EntityCommon.init(pk, sk, dc, logging.MustGetLogger("dmsg_client"))
	c.EntityCommon.setSessionCallback = func(ctx context.Context) error {
		return c.EntityCommon.updateClientEntry(ctx, c.done)
	}
	c.EntityCommon.delSessionCallback = func(ctx context.Context) error {
		return c.EntityCommon.updateClientEntry(ctx, c.done)
	}

	return c
}

// Serve serves the client.
// It blocks until the client is closed.
func (ce *ClientEntity) Serve() {
	defer func() {
		ce.log.Info("Stopped serving client!")
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func(ctx context.Context) {
		awaitDone(ctx, ce.done)
		cancel()
	}(ctx)

	for {
		if isClosed(ce.done) {
			return
		}

		ce.log.Info("Discovering dmsg servers...")
		entries, err := ce.discoverServers(ctx)
		if err != nil {
			ce.log.WithError(err).Warn("Failed to discover dmsg servers.")
			time.Sleep(time.Second) // TODO(evanlinjin): Implement exponential back off.
			continue
		}

		for _, entry := range entries {
			if isClosed(ce.done) {
				return
			}

			// If we have enough sessions, we wait for error or done signal.
			if ce.SessionCount() >= ce.conf.MinSessions {
				select {
				case <-ce.done:
					return
				case err := <-ce.errCh:
					ce.log.WithError(err).Info("Session stopped.")
				}
			}

			if err := ce.ensureSession(ctx, entry); err != nil {
				ce.log.WithField("remote_pk", entry.Static).WithError(err).Warn("Failed to establish session.")
			}
		}
	}
}

func (ce *ClientEntity) discoverServers(ctx context.Context) (entries []*disc.Entry, err error) {
	err = netutil.NewDefaultRetrier(ce.log).Do(ctx, func() error {
		entries, err = ce.dc.AvailableServers(ctx)
		return err
	})
	return entries, err
}

// Close closes the dmsg client entity.
// TODO(evanlinjin): Have waitgroup.
func (ce *ClientEntity) Close() error {
	if ce == nil {
		return nil
	}

	ce.once.Do(func() {
		close(ce.done)

		ce.sesMx.Lock()
		close(ce.errCh)
		ce.sesMx.Unlock()

		ce.mx.Lock()
		for _, dSes := range ce.ss {
			ce.log.
				WithError(dSes.Close()).
				Info("Session closed.")
		}
		ce.ss = make(map[cipher.PubKey]*SessionCommon)
		ce.log.Info("All sessions closed.")
		ce.mx.Unlock()

		ce.porter.RangePortValues(func(port uint16, v interface{}) (next bool) {
			if v != nil {
				switch v.(type) {
				case *Listener:
					ce.log.
						WithError(v.(*Listener).Close()).
						Info("Listener closed.")
				case *Stream:
					ce.log.
						WithError(v.(*Stream).Close()).
						Info("Stream closed.")
				}
			}
			return true
		})
	})

	return nil
}

// Listen listens on a given dmsg port.
func (ce *ClientEntity) Listen(port uint16) (*Listener, error) {
	lis := newListener(Addr{PK: ce.pk, Port: port})
	ok, doneFn := ce.porter.Reserve(port, lis)
	if !ok {
		lis.close()
		return nil, ErrPortOccupied
	}
	lis.addCloseCallback(doneFn)
	return lis, nil
}

// DialStream dials to a remote client entity with the given address.
func (ce *ClientEntity) DialStream(ctx context.Context, addr Addr) (*Stream, error) {
	entry, err := getClientEntry(ctx, ce.dc, addr.PK)
	if err != nil {
		return nil, err
	}

	// Range client's delegated servers.
	// See if we are already connected to a delegated server.
	for _, srvPK := range entry.Client.DelegatedServers {
		if dSes, ok := ce.ClientSession(ce.porter, srvPK); ok {
			return dSes.DialStream(addr)
		}
	}

	// Range client's delegated servers.
	// Attempt to connect to a delegated server.
	for _, srvPK := range entry.Client.DelegatedServers {
		dSes, err := ce.obtainSession(ctx, srvPK)
		if err != nil {
			continue
		}
		return dSes.DialStream(addr)
	}

	return nil, ErrCannotConnectToDelegated
}

// ensureSession ensures the existence of a session.
// It returns an error if the session does not exist AND cannot be established.
func (ce *ClientEntity) ensureSession(ctx context.Context, entry *disc.Entry) error {
	ce.sesMx.Lock()
	defer ce.sesMx.Unlock()

	// If session with server of pk already exists, skip.
	if _, ok := ce.ClientSession(ce.porter, entry.Static); ok {
		return nil
	}

	// Dial session.
	_, err := ce.dialSession(ctx, entry)
	return err
}

func (ce *ClientEntity) obtainSession(ctx context.Context, srvPK cipher.PubKey) (ClientSession, error) {
	ce.sesMx.Lock()
	defer ce.sesMx.Unlock()

	if dSes, ok := ce.ClientSession(ce.porter, srvPK); ok {
		return dSes, nil
	}

	srvEntry, err := getServerEntry(ctx, ce.dc, srvPK)
	if err != nil {
		return ClientSession{}, err
	}

	return ce.dialSession(ctx, srvEntry)
}

// It is expected that the session is created and served before the context cancels, otherwise an error will be returned.
// NOTE: This should not be called directly as it may lead to session duplicates.
// Only `ensureSession` or `obtainSession` should call this function.
func (ce *ClientEntity) dialSession(ctx context.Context, entry *disc.Entry) (ClientSession, error) {
	ce.log.WithField("remote_pk", entry.Static).Info("Dialing session...")

	conn, err := net.Dial("tcp", entry.Server.Address)
	if err != nil {
		return ClientSession{}, err
	}
	dSes, err := makeClientSession(&ce.EntityCommon, ce.porter, conn, entry.Static)
	if err != nil {
		return ClientSession{}, err
	}

	if !ce.setSession(ctx, dSes.SessionCommon) {
		_ = dSes.Close() //nolint:errcheck
		return ClientSession{}, errors.New("session already exists")
	}
	go func() {
		ce.log.WithField("remote_pk", dSes.RemotePK()).Info("Serving session.")
		if err := dSes.Serve(); !isClosed(ce.done) {
			ce.errCh <- err
			ce.delSession(ctx, dSes.RemotePK())
		}
	}()

	return dSes, nil
}