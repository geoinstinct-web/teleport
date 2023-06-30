package pgbk

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/test"
	"github.com/gravitational/teleport/lib/utils"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

func TestPostgresBackend(t *testing.T) {
	paramString := os.Getenv("TELEPORT_PGBK_TEST_PARAMS_JSON")
	if paramString == "" {
		t.Skip("Postgres backend tests are disabled. Enable them by setting the TELEPORT_PGBK_TEST_PARAMS_JSON variable.")
	}

	newBackend := func(options ...test.ConstructionOption) (backend.Backend, clockwork.FakeClock, error) {
		testCfg, err := test.ApplyOptions(options)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		if testCfg.MirrorMode {
			return nil, nil, test.ErrMirrorNotSupported
		}

		if testCfg.ConcurrentBackend != nil {
			return nil, nil, test.ErrConcurrentAccessNotSupported
		}

		var params backend.Params
		require.NoError(t, json.Unmarshal([]byte(paramString), &params))

		uut, err := New(context.Background(), params)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		return uut, blockingFakeClock{clockwork.NewRealClock()}, nil
	}

	test.RunBackendComplianceSuite(t, newBackend)
}

// TODO(espadolini): use the one used by etcd and firestore
type blockingFakeClock struct {
	clockwork.Clock
}

func (r blockingFakeClock) Advance(d time.Duration) {
	if d < 0 {
		panic("cannot rewind real clock")
	}

	r.Clock.Sleep(d)
}

func (r blockingFakeClock) BlockUntil(n int) {
	panic("BlockUntil not implemented")
}
