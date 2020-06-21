package dmsgget

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/SkycoinProject/skycoin/src/util/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"

	"github.com/SkycoinProject/dmsg"
	"github.com/SkycoinProject/dmsg/cipher"
	"github.com/SkycoinProject/dmsg/disc"
	"github.com/SkycoinProject/dmsg/dmsghttp"
)

const (
	nSrvs       = 2
	maxSessions = 100
)

// Serve a HTTP server over dmsg, and have multiple clients download a document simultaneously.
// Arrange:
// - Typical dmsg environment.
// - Dmsg client that serves a HTTP server.
// Act:
// - Start multiple dmsg clients that download from the HTTP server.
// Assert:
// - Ensure the downloads all succeed.
// - Ensure the downloaded data (of all downloads) is the same as the original document.
func TestDownload(t *testing.T) {
	const (
		fileSize  = 512
		dlClients = 10 // number of clients to download from HTTP server.
	)

	// Arrange: Prepare file to be downloaded.
	srcData := cipher.RandByte(fileSize)
	src := makeFile(t, srcData)

	// Arrange: Start dmsg environment.
	dc := startDmsgEnv(t, nSrvs, maxSessions)

	// Arrange: Start dmsg client that serves a http server which hosts the src file.
	hsAddr := runHTTPSrv(t, dc, src.Name())

	// Arrange: Download results (dst files and client errors).
	dsts := make([]*os.File, dlClients)
	errs := make([]chan error, dlClients)
	for i := range dsts {
		dsts[i] = makeFile(t, nil)
		errs[i] = make(chan error, 1)
	}

	// Act: Download
	for i := 0; i < dlClients; i++ {
		func(i int) {
			log := logging.MustGetLogger(fmt.Sprintf("dl_client_%d", i))
			err := Download(log, newHTTPClient(t, dc), dsts[i], hsAddr)

			errs[i] <- err
			close(errs[i])
		}(i)
	}

	// Assert: Ensure download finishes without error and downloaded file is the same as src.
	for i := 0; i < dlClients; i++ {
		assert.NoError(t, <-errs[i])

		dstData, err := ioutil.ReadFile(dsts[i].Name())
		assert.NoErrorf(t, err, "[%d] failed to read destination file", i)
		assert.Equalf(t, srcData, dstData, "[%d] destination file data is not equal", i)
	}
}

func makeFile(t *testing.T, data []byte) *os.File {
	f, err := ioutil.TempFile(os.TempDir(), "dmsgget_test_file_*")
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, f.Close())
		assert.NoError(t, os.Remove(f.Name()))
	})

	if data != nil {
		n, err := f.Write(data)
		require.NoError(t, err)
		require.Len(t, data, n)
	}

	return f
}

func startDmsgEnv(t *testing.T, nSrvs, maxSessions int) disc.APIClient {
	dc := disc.NewMock(0)

	for i := 0; i < nSrvs; i++ {
		pk, sk := cipher.GenerateKeyPair()

		conf := dmsg.ServerConfig{
			MaxSessions:    maxSessions,
			UpdateInterval: 0,
		}
		srv := dmsg.NewServer(pk, sk, dc, &conf, nil)
		srv.SetLogger(logging.MustGetLogger(fmt.Sprintf("server_%d", i)))

		lis, err := nettest.NewLocalListener("tcp")
		require.NoError(t, err)

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Serve(lis, "")
			close(errCh)
		}()

		t.Cleanup(func() {
			// listener is also closed when dmsg server is closed
			assert.NoError(t, srv.Close())
			assert.NoError(t, <-errCh)
		})
	}

	return dc
}

func runHTTPSrv(t *testing.T, dc disc.APIClient, fName string) string {
	pk, sk := cipher.GenerateKeyPair()
	httpPath := filepath.Base(fName)

	dmsgC := dmsg.NewClient(pk, sk, dc, nil)
	go dmsgC.Serve()
	t.Cleanup(func() { assert.NoError(t, dmsgC.Close()) })
	<-dmsgC.Ready()

	mux := http.NewServeMux()
	mux.HandleFunc("/"+httpPath, func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, fName)
	})

	lis, err := dmsgC.Listen(80)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		errCh <- http.Serve(lis, mux)
		close(errCh)
	}()

	t.Cleanup(func() {
		assert.NoError(t, lis.Close())
		assert.EqualError(t, <-errCh, dmsg.ErrEntityClosed.Error())
	})

	return fmt.Sprintf("http://%s/%s", pk.String(), httpPath)
}

func newHTTPClient(t *testing.T, dc disc.APIClient) *http.Client {
	pk, sk := cipher.GenerateKeyPair()

	dmsgC := dmsg.NewClient(pk, sk, dc, nil)
	go dmsgC.Serve()
	t.Cleanup(func() { assert.NoError(t, dmsgC.Close()) })
	<-dmsgC.Ready()

	return &http.Client{Transport: dmsghttp.MakeHTTPTransport(dmsgC)}
}
