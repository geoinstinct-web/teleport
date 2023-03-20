/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

const (
	scanDuration = time.Hour * 24 * 30
	indexName    = "timesearchV2"
)

func main() {
	params, err := getParams()
	if err != nil {
		log.Fatal(err)
	}

	// create an AWS session using default SDK behavior, i.e. it will interpret
	// the environment and ~/.aws directory just like an AWS CLI tool would:
	session, err := awssession.NewSessionWithOptions(awssession.Options{
		SharedConfigState: awssession.SharedConfigEnable,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Assume a base read capacity of 25 units per second to start off.
	// If this is too high and we encounter throttling that could impede Teleport, it will be adjusted automatically.
	limiter := newAdaptiveRateLimiter(25)

	// Reduce internal retry count so throttling errors bubble up to our rate limiter with less delay.
	svc := dynamodb.New(session, &aws.Config{
		MaxRetries: aws.Int(1),
		Region:     aws.String(params.awsRegion),
	})

	// sets of unique users for calculating MAU
	state := &trackedState{
		ssh:     make(map[string]struct{}),
		kube:    make(map[string]struct{}),
		db:      make(map[string]struct{}),
		app:     make(map[string]struct{}),
		desktop: make(map[string]struct{}),
	}

	fmt.Println("Gathering data, this may take a moment")
	for _, date := range daysBetween(params.startDate, params.startDate.Add(scanDuration)) {
		err := scanDay(svc, limiter, params.tableName, date, state)
		if err != nil {
			log.Fatal(err)
		}
	}

	startDate := params.startDate.Format(time.DateOnly)
	endDate := params.startDate.Add(scanDuration).Format(time.DateOnly)
	fmt.Printf("Monthly active users by product during the period %v to %v:\n  Server Access: %d\n  Kubernetes Access: %d\n  Database Access: %d\n  Application Access: %d\n  Desktop Access: %d\n", startDate, endDate, len(state.ssh), len(state.kube), len(state.db), len(state.app), len(state.desktop))
}

// scanDay scans a single day of events from the audit log table.
func scanDay(svc *dynamodb.DynamoDB, limiter *adaptiveRateLimiter, tableName string, date string, state *trackedState) error {
	attributes := map[string]interface{}{
		":date": date,
		":e1":   "session.start",
		":e2":   "db.session.start",
		":e3":   "app.session.start",
		":e4":   "windows.desktop.session.start",
	}

	attributeValues, err := dynamodbattribute.MarshalMap(attributes)
	if err != nil {
		return err
	}

	var paginationKey map[string]*dynamodb.AttributeValue
	pageCount := 1

outer:
	for {
		fmt.Printf("  scanning date %v page %v...\n", date, pageCount)
		scanOut, err := svc.Query(&dynamodb.QueryInput{
			TableName:                 aws.String(tableName),
			IndexName:                 aws.String(indexName),
			KeyConditionExpression:    aws.String("CreatedAtDate = :date"),
			ExpressionAttributeValues: attributeValues,
			FilterExpression:          aws.String("EventType IN (:e1, :e2, :e3, :e4)"),
			ExclusiveStartKey:         paginationKey,
			ReturnConsumedCapacity:    aws.String(dynamodb.ReturnConsumedCapacityTotal),
			// We limit the number of items returned to the current capacity to minimize any usage spikes
			// that could affect Teleport as RCUs may be consumed for multiple seconds if the response is large, slowing down Teleport significantly.
			Limit: aws.Int64(int64(limiter.CurrentCapacity())),
		})
		switch {
		case err != nil && err.Error() == dynamodb.ErrCodeProvisionedThroughputExceededException:
			fmt.Println("  throttled by DynamoDB, adjusting request rate...")
			limiter.ReportThrottleError()
			continue outer
		case err != nil:
			return err
		}

		pageCount++
		limiter.Wait(*scanOut.ConsumedCapacity.CapacityUnits)
		err = reduceEvents(scanOut.Items, state)
		if err != nil {
			return err
		}

		paginationKey = scanOut.LastEvaluatedKey
		if paginationKey == nil {
			break
		}
	}

	return nil
}

type event struct {
	EventType string
	FieldsMap struct {
		User              string
		KubernetesCluster *string `dynamodbav:"kubernetes_cluster,omitempty"`
	}
}

// applies a set of scanned raw events onto the tracked state.
func reduceEvents(rawEvents []map[string]*dynamodb.AttributeValue, state *trackedState) error {
	for _, rawEvent := range rawEvents {
		var event event
		err := dynamodbattribute.UnmarshalMap(rawEvent, &event)
		if err != nil {
			log.Fatal(err)
		}

		var set map[string]struct{}
		switch event.EventType {
		case "session.start":
			set = state.ssh

			if event.FieldsMap.KubernetesCluster != nil {
				set = state.kube
			}
		case "db.session.start":
			set = state.db
		case "app.session.start":
			set = state.app
		case "windows.desktop.session.start":
			set = state.desktop
		default:
			return errors.New("unexpected event type: " + event.EventType)
		}

		set[event.FieldsMap.User] = struct{}{}
	}

	return nil
}

// daysBetween returns a list of all dates between `start` and `end` in the format `yyyy-mm-dd`.
func daysBetween(start, end time.Time) []string {
	var days []string
	oneDay := time.Hour * time.Duration(24)
	startDay := daysSinceEpoch(start)
	endDay := daysSinceEpoch(end)

	for startDay <= endDay {
		days = append(days, start.Format(time.DateOnly))
		startDay++
		start = start.Add(oneDay)
	}

	return days
}

func daysSinceEpoch(timestamp time.Time) int64 {
	return timestamp.Unix() / (60 * 60 * 24)
}

// trackedState is a set of unique users for each protocol.
type trackedState struct {
	ssh     map[string]struct{}
	kube    map[string]struct{}
	db      map[string]struct{}
	app     map[string]struct{}
	desktop map[string]struct{}
}

type params struct {
	tableName string
	awsRegion string
	startDate time.Time
}

func getParams() (params, error) {
	tableName := os.Getenv("TABLE_NAME")
	awsRegion := os.Getenv("AWS_REGION")
	startDate := os.Getenv("START_DATE")

	if tableName == "" {
		return params{}, errors.New("TABLE_NAME environment variable is required")
	}

	if awsRegion == "" {
		return params{}, errors.New("AWS_REGION environment variable is required")
	}

	var timestamp time.Time
	var err error
	if startDate == "" {
		timestamp = time.Now().UTC().Add(-scanDuration)
	} else {
		timestamp, err = time.Parse(time.DateOnly, startDate)
		if err != nil {
			return params{}, err
		}
	}

	return params{
		tableName: tableName,
		awsRegion: awsRegion,
		startDate: timestamp,
	}, nil
}

// adaptiveRateLimiter is a rate limiter that dynamically adjusts its request rate based on throttling errors.
// This unusual strategy was chosen since we cannot know how much free read capacity is available.
//
// This rate limiter progressively increases the request rate when it is not throttled for a longer period of time, and decreases it when it is.
//
// This will never cause actual interrupts to the Teleport since the AWS SDK there will retry generously to smooth over
// any possible retries caused by us. The important element is that we back off as soon as we notice this which
// allows Teleport to success eventually.
type adaptiveRateLimiter struct {
	permitCapacity float64
	streak         int
}

func (a *adaptiveRateLimiter) ReportThrottleError() {
	a.permitCapacity *= 0.85
	a.streak = 0
}

func (a *adaptiveRateLimiter) Wait(permits float64) {
	durationToWait := time.Duration(permits / a.permitCapacity * float64(time.Second))
	time.Sleep(durationToWait)

	a.streak++
	if a.streak > 10 {
		a.streak = 0
		a.permitCapacity *= 1.1
	}
}

func (a *adaptiveRateLimiter) CurrentCapacity() float64 {
	return a.permitCapacity
}

func newAdaptiveRateLimiter(permitsPerSecond float64) *adaptiveRateLimiter {
	return &adaptiveRateLimiter{
		permitCapacity: permitsPerSecond,
	}
}
