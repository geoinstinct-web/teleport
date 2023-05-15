// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package athena

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/utils"
)

func Test_consumer_sqsMessagesCollector(t *testing.T) {
	// channelClosedCondition returns function that can be used to check if eventually
	// channel was closed.
	channelClosedCondition := func(t *testing.T, ch <-chan eventAndAckID) func() bool {
		return func() bool {
			select {
			case _, ok := <-ch:
				if ok {
					t.Log("Received unexpected message")
					t.Fail()
					return false
				} else {
					// channel is closed, that's what we are waiting for.
					return true
				}
			default:
				// retry
				return false
			}
		}
	}

	maxWaitTimeOnReceiveMessagesInFake := 5 * time.Millisecond
	maxWaitOnResults := 200 * time.Millisecond

	t.Run("verify if events are sent over channel", func(t *testing.T) {
		// Given SqsMessagesCollector reading from fake sqs with random wait time on receiveMessage call
		// When 3 messages are published
		// Then 3 messages can be received from eventsChan.

		// Given
		fclock := clockwork.NewFakeClock()
		fq := &fakeSQS{
			clock:       fclock,
			maxWaitTime: maxWaitTimeOnReceiveMessagesInFake,
		}
		cfg := validCollectCfgForTests(t)
		cfg.sqsReceiver = fq
		require.NoError(t, cfg.CheckAndSetDefaults())
		c := newSqsMessagesCollector(cfg)
		eventsChan := c.getEventsChan()

		readSQSCtx, readCancel := context.WithCancel(context.Background())
		defer readCancel()
		go c.fromSQS(readSQSCtx)

		// receiver is used to read messages from eventsChan.
		r := &receiver{}
		go r.Do(eventsChan)

		// When
		wantEvents := []apievents.AuditEvent{
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}, AppMetadata: apievents.AppMetadata{AppName: "app1"}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}, AppMetadata: apievents.AppMetadata{AppName: "app2"}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}, AppMetadata: apievents.AppMetadata{AppName: "app3"}},
		}
		fq.addEvents(wantEvents...)
		// Advance clock to simulate random wait time on receive messages endpoint.
		fclock.BlockUntil(cfg.noOfWorkers)
		fclock.Advance(maxWaitTimeOnReceiveMessagesInFake)

		// Then
		require.Eventually(t, func() bool {
			return len(r.GetMsgs()) == 3
		}, maxWaitOnResults, 1*time.Millisecond)
		requireEventsEqualInAnyOrder(t, wantEvents, eventAndAckIDToAuditEvents(r.GetMsgs()))
	})

	t.Run("verify if collector finishes execution (via closing channel) upon ctx.Cancel", func(t *testing.T) {
		// Given SqsMessagesCollector reading from fake sqs with random wait time on receiveMessage call
		// When ctx is canceled
		// Then reading chan is closed.

		// Given
		fclock := clockwork.NewFakeClock()
		fq := &fakeSQS{
			clock:       fclock,
			maxWaitTime: maxWaitTimeOnReceiveMessagesInFake,
		}
		cfg := validCollectCfgForTests(t)
		cfg.sqsReceiver = fq
		require.NoError(t, cfg.CheckAndSetDefaults())
		c := newSqsMessagesCollector(cfg)
		eventsChan := c.getEventsChan()

		readSQSCtx, readCancel := context.WithCancel(context.Background())
		go c.fromSQS(readSQSCtx)

		// When
		readCancel()

		// Then
		// Make sure that channel is closed.
		require.Eventually(t, channelClosedCondition(t, eventsChan), maxWaitOnResults, 1*time.Millisecond)
	})

	t.Run("verify if collector finishes execution (via closing channel) upon reaching batchMaxItems", func(t *testing.T) {
		// Given SqsMessagesCollector reading from fake sqs with random wait time on receiveMessage call
		// When batchMaxItems is reached.
		// Then reading chan is closed.

		// Given
		fclock := clockwork.NewFakeClock()
		fq := &fakeSQS{
			clock:       fclock,
			maxWaitTime: maxWaitTimeOnReceiveMessagesInFake,
		}
		cfg := validCollectCfgForTests(t)
		cfg.sqsReceiver = fq
		cfg.batchMaxItems = 3
		require.NoError(t, cfg.CheckAndSetDefaults())
		c := newSqsMessagesCollector(cfg)

		eventsChan := c.getEventsChan()

		readSQSCtx, readCancel := context.WithCancel(context.Background())
		defer readCancel()

		go c.fromSQS(readSQSCtx)

		// receiver is used to read messages from eventsChan.
		r := &receiver{}
		go r.Do(eventsChan)

		// When
		wantEvents := []apievents.AuditEvent{
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}, AppMetadata: apievents.AppMetadata{AppName: "app1"}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}, AppMetadata: apievents.AppMetadata{AppName: "app2"}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}, AppMetadata: apievents.AppMetadata{AppName: "app3"}},
		}
		fq.addEvents(wantEvents...)
		fclock.BlockUntil(cfg.noOfWorkers)
		fclock.Advance(maxWaitTimeOnReceiveMessagesInFake)
		require.Eventually(t, func() bool {
			return len(r.GetMsgs()) == 3
		}, maxWaitOnResults, 1*time.Millisecond)

		// Then
		// Make sure that channel is closed.
		require.Eventually(t, channelClosedCondition(t, eventsChan), maxWaitOnResults, 1*time.Millisecond)
		requireEventsEqualInAnyOrder(t, wantEvents, eventAndAckIDToAuditEvents(r.GetMsgs()))
	})
}

func validCollectCfgForTests(t *testing.T) sqsCollectConfig {
	return sqsCollectConfig{
		sqsReceiver:       &mockReceiver{},
		queueURL:          "test-queue",
		payloadBucket:     "bucket",
		payloadDownloader: &fakeS3manager{},
		logger:            utils.NewLoggerForTests(),
		errHandlingFn: func(ctx context.Context, errC chan error) {
			err, ok := <-errC
			if ok && err != nil {
				// we don't expect error in that test case.
				t.Log("Unexpected error", err)
				t.Fail()
			}
		},
	}
}

type fakeSQS struct {
	mu          sync.Mutex
	msgs        []sqsTypes.Message
	clock       clockwork.Clock
	maxWaitTime time.Duration
}

func (f *fakeSQS) addEvents(events ...apievents.AuditEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range events {
		f.msgs = append(f.msgs, rawProtoMessage(e))
	}
}

func (f *fakeSQS) ReceiveMessage(ctx context.Context, params *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	// Let's use random sleep duration. That's how sqs works, you could wait up until max wait time but
	// it can return earlier.

	randInt, err := rand.Int(rand.Reader, big.NewInt(f.maxWaitTime.Nanoseconds()))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.clock.After(time.Duration(randInt.Int64())):
		// continue below
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) > 0 {
		out := &sqs.ReceiveMessageOutput{
			Messages: f.msgs,
		}
		f.msgs = nil
		return out, nil
	}
	return &sqs.ReceiveMessageOutput{}, nil
}

type receiver struct {
	mu   sync.Mutex
	msgs []eventAndAckID
}

func (f *receiver) Do(eventsChan <-chan eventAndAckID) {
	for e := range eventsChan {
		f.mu.Lock()
		f.msgs = append(f.msgs, e)
		f.mu.Unlock()
	}
}

func (f *receiver) GetMsgs() []eventAndAckID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.msgs
}

func eventAndAckIDToAuditEvents(in []eventAndAckID) []apievents.AuditEvent {
	var out []apievents.AuditEvent
	for _, eventAndAckID := range in {
		out = append(out, eventAndAckID.event)
	}
	return out
}

func rawProtoMessage(in apievents.AuditEvent) sqsTypes.Message {
	oneOf := apievents.MustToOneOf(in)
	bb, err := oneOf.Marshal()
	if err != nil {
		panic(err)
	}
	return sqsTypes.Message{
		Body: aws.String(base64.StdEncoding.EncodeToString(bb)),
		MessageAttributes: map[string]sqsTypes.MessageAttributeValue{
			payloadTypeAttr: {StringValue: aws.String(payloadTypeRawProtoEvent)},
		},
		ReceiptHandle: aws.String(uuid.NewString()),
	}
}

// TestSQSMessagesCollectorErrorsOnReceive verifies that workers fetching events
// from ReceiveMessage endpoint, will wait specified interval before retrying
// after receiving error from API call.
func TestSQSMessagesCollectorErrorsOnReceive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	mockReceiver := &mockReceiver{
		receiveMessageRespFn: func() (*sqs.ReceiveMessageOutput, error) {
			return nil, errors.New("aws error")
		},
	}

	errHandlingFn := func(ctx context.Context, errC chan error) {
		require.ErrorContains(t, trace.NewAggregateFromChannel(errC, ctx), "aws error")
	}
	waitIntervalOnReceiveError := 5 * time.Millisecond
	noOfWorker := 2
	iterationsToWait := 4
	expectedNoOfCalls := noOfWorker * iterationsToWait

	cfg := validCollectCfgForTests(t)
	cfg.sqsReceiver = mockReceiver
	cfg.noOfWorkers = noOfWorker
	cfg.waitOnReceiveError = waitIntervalOnReceiveError
	cfg.errHandlingFn = errHandlingFn
	require.NoError(t, cfg.CheckAndSetDefaults())
	c := newSqsMessagesCollector(cfg)

	eventsChan := c.getEventsChan()
	sqsCtx, sqsCancel := context.WithCancel(ctx)
	go c.fromSQS(sqsCtx)

	<-time.After(time.Duration(iterationsToWait) * waitIntervalOnReceiveError)
	sqsCancel()
	select {
	case <-ctx.Done():
		t.Fatal("Collector never finished")
	case _, ok := <-eventsChan:
		require.False(t, ok, "No data should be sent on events channel")
	}

	gotNoOfCalls := mockReceiver.getNoOfCalls()
	// We can't be sure that there will be equaly noOfCalls as expected,
	// because they are process in async way, that's why margin in EquateApprox is used.
	require.Empty(t, cmp.Diff(float32(gotNoOfCalls), float32(expectedNoOfCalls), cmpopts.EquateApprox(0, 4)))
}

type mockReceiver struct {
	receiveMessageRespFn  func() (*sqs.ReceiveMessageOutput, error)
	receiveMessageCountMu sync.Mutex
	receiveMessageCount   int
}

func (m *mockReceiver) getNoOfCalls() int {
	m.receiveMessageCountMu.Lock()
	defer m.receiveMessageCountMu.Unlock()
	return m.receiveMessageCount
}

func (m *mockReceiver) ReceiveMessage(ctx context.Context, params *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	m.receiveMessageCountMu.Lock()
	m.receiveMessageCount++
	m.receiveMessageCountMu.Unlock()
	return m.receiveMessageRespFn()
}

func TestRunWithMinInterval(t *testing.T) {
	ctx := context.Background()
	t.Run("function returns earlier than minInterval, wait should happen", func(t *testing.T) {
		fn := func(ctx context.Context) bool {
			// did not reached max size
			return false
		}
		minInterval := 5 * time.Millisecond
		start := time.Now()
		stop := runWithMinInterval(ctx, fn, minInterval)
		elapsed := time.Since(start)
		require.False(t, stop)
		require.GreaterOrEqual(t, elapsed, minInterval)
	})

	t.Run("function takes longer than minInterval, noting more should happen", func(t *testing.T) {
		minInterval := 5 * time.Millisecond
		fn := func(ctx context.Context) bool {
			// did not reached max size
			select {
			case <-time.After(2 * minInterval):
				return false
			case <-ctx.Done():
				return false
			}
		}
		start := time.Now()
		stop := runWithMinInterval(ctx, fn, minInterval)
		elapsed := time.Since(start)
		require.False(t, stop)
		require.GreaterOrEqual(t, elapsed, 2*minInterval)
	})

	t.Run("reached maxBatchSize, wait should not happen", func(t *testing.T) {
		fn := func(ctx context.Context) bool {
			return true
		}
		minInterval := 5 * time.Millisecond
		start := time.Now()
		stop := runWithMinInterval(ctx, fn, minInterval)
		elapsed := time.Since(start)
		require.False(t, stop)
		require.Less(t, elapsed, minInterval)
	})

	t.Run("context is canceled, make sure that stop is returned.", func(t *testing.T) {
		minInterval := 5 * time.Millisecond
		fn := func(ctx context.Context) bool {
			// did not reached max size
			select {
			case <-time.After(minInterval):
				return false
			case <-ctx.Done():
				return false
			}
		}
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		stop := runWithMinInterval(ctx, fn, minInterval)
		require.True(t, stop)
	})
}

func TestErrHandlingFnFromSQS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	log := utils.NewLoggerForTests()
	// buf is used as output of logs, that we will use for assertions.
	var buf bytes.Buffer
	log.SetOutput(&buf)

	t.Run("a lot of errors, make sure only up to maxErrorCountForLogsOnSQSReceive are printed and total count", func(t *testing.T) {
		buf.Reset()
		noOfErrors := maxErrorCountForLogsOnSQSReceive + 1
		errorC := make(chan error, noOfErrors)
		go func() {
			for i := 0; i < noOfErrors; i++ {
				errorC <- errors.New("some error")
			}
			close(errorC)
		}()
		errHandlingFnFromSQS(log)(ctx, errorC)
		require.Equal(t, maxErrorCountForLogsOnSQSReceive, strings.Count(buf.String(), "some error"), "number of error log messages does not match")
		require.Contains(t, buf.String(), fmt.Sprintf("Got %d errors from SQS collector, printed only first", noOfErrors))
	})

	t.Run("few errors, no total count should be printed", func(t *testing.T) {
		buf.Reset()
		noOfErrors := 5
		errorC := make(chan error, noOfErrors)
		go func() {
			for i := 0; i < noOfErrors; i++ {
				errorC <- errors.New("some error")
			}
			close(errorC)
		}()
		errHandlingFnFromSQS(log)(ctx, errorC)
		require.Equal(t, noOfErrors, strings.Count(buf.String(), "some error"), "number of error log messages does not match")
		require.NotContains(t, buf.String(), "printed only first")
	})
	t.Run("no errors at all", func(t *testing.T) {
		buf.Reset()
		errorC := make(chan error, 10)
		go func() {
			// close without any errors sent means receiving loop finished without any err
			close(errorC)
		}()
		errHandlingFnFromSQS(log)(ctx, errorC)
		require.Empty(t, buf.String())
	})
	t.Run("no errors at all - stopped via ctx cancel", func(t *testing.T) {
		buf.Reset()
		errorC := make(chan error, 10)
		defer close(errorC)

		ctx, inCancel := context.WithCancel(ctx)
		inCancel()

		errHandlingFnFromSQS(log)(ctx, errorC)
		require.Empty(t, buf.String())
	})

	t.Run("there were a lot of errors, stopped via ctx cancel", func(t *testing.T) {
		buf.Reset()
		// unbuffered channel and a more messages,
		// just make sure that errors are processed
		// before cancel happen, used to avoid sleeping.
		noOfErrors := maxErrorCountForLogsOnSQSReceive + 10

		errorC := make(chan error)
		defer close(errorC)

		ctx, inCancel := context.WithCancel(ctx)
		go func() {
			for i := 0; i < noOfErrors; i++ {
				errorC <- errors.New("some error")
			}
			inCancel()
		}()

		errHandlingFnFromSQS(log)(ctx, errorC)
		require.Equal(t, maxErrorCountForLogsOnSQSReceive, strings.Count(buf.String(), "some error"), "number of error log messages does not match")
		require.Contains(t, buf.String(), "printed only first")
	})
}
