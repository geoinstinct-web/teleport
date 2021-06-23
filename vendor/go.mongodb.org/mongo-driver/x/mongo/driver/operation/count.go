// Copyright (C) MongoDB, Inc. 2019-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Code generated by operationgen. DO NOT EDIT.

package operation

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo/description"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"go.mongodb.org/mongo-driver/x/mongo/driver"
	"go.mongodb.org/mongo-driver/x/mongo/driver/session"
)

// Performs a count operation
type Count struct {
	maxTimeMS      *int64
	query          bsoncore.Document
	session        *session.Client
	clock          *session.ClusterClock
	collection     string
	monitor        *event.CommandMonitor
	crypt          *driver.Crypt
	database       string
	deployment     driver.Deployment
	readConcern    *readconcern.ReadConcern
	readPreference *readpref.ReadPref
	selector       description.ServerSelector
	retry          *driver.RetryMode
	result         CountResult
}

type CountResult struct {
	// The number of documents found
	N int64
}

func buildCountResult(response bsoncore.Document, srvr driver.Server) (CountResult, error) {
	elements, err := response.Elements()
	if err != nil {
		return CountResult{}, err
	}
	cr := CountResult{}
	for _, element := range elements {
		switch element.Key() {
		case "n":
			var ok bool
			cr.N, ok = element.Value().AsInt64OK()
			if !ok {
				err = fmt.Errorf("response field 'n' is type int64, but received BSON type %s", element.Value().Type)
			}
		}
	}
	return cr, nil
}

// NewCount constructs and returns a new Count.
func NewCount() *Count {
	return &Count{}
}

// Result returns the result of executing this operation.
func (c *Count) Result() CountResult { return c.result }

func (c *Count) processResponse(response bsoncore.Document, srvr driver.Server, desc description.Server, _ int) error {
	var err error
	c.result, err = buildCountResult(response, srvr)
	return err
}

// Execute runs this operations and returns an error if the operaiton did not execute successfully.
func (c *Count) Execute(ctx context.Context) error {
	if c.deployment == nil {
		return errors.New("the Count operation must have a Deployment set before Execute can be called")
	}

	return driver.Operation{
		CommandFn:         c.command,
		ProcessResponseFn: c.processResponse,
		RetryMode:         c.retry,
		Type:              driver.Read,
		Client:            c.session,
		Clock:             c.clock,
		CommandMonitor:    c.monitor,
		Crypt:             c.crypt,
		Database:          c.database,
		Deployment:        c.deployment,
		ReadConcern:       c.readConcern,
		ReadPreference:    c.readPreference,
		Selector:          c.selector,
	}.Execute(ctx, nil)

}

func (c *Count) command(dst []byte, desc description.SelectedServer) ([]byte, error) {
	dst = bsoncore.AppendStringElement(dst, "count", c.collection)
	if c.maxTimeMS != nil {
		dst = bsoncore.AppendInt64Element(dst, "maxTimeMS", *c.maxTimeMS)
	}
	if c.query != nil {
		dst = bsoncore.AppendDocumentElement(dst, "query", c.query)
	}
	return dst, nil
}

// MaxTimeMS specifies the maximum amount of time to allow the query to run.
func (c *Count) MaxTimeMS(maxTimeMS int64) *Count {
	if c == nil {
		c = new(Count)
	}

	c.maxTimeMS = &maxTimeMS
	return c
}

// Query determines what results are returned from find.
func (c *Count) Query(query bsoncore.Document) *Count {
	if c == nil {
		c = new(Count)
	}

	c.query = query
	return c
}

// Session sets the session for this operation.
func (c *Count) Session(session *session.Client) *Count {
	if c == nil {
		c = new(Count)
	}

	c.session = session
	return c
}

// ClusterClock sets the cluster clock for this operation.
func (c *Count) ClusterClock(clock *session.ClusterClock) *Count {
	if c == nil {
		c = new(Count)
	}

	c.clock = clock
	return c
}

// Collection sets the collection that this command will run against.
func (c *Count) Collection(collection string) *Count {
	if c == nil {
		c = new(Count)
	}

	c.collection = collection
	return c
}

// CommandMonitor sets the monitor to use for APM events.
func (c *Count) CommandMonitor(monitor *event.CommandMonitor) *Count {
	if c == nil {
		c = new(Count)
	}

	c.monitor = monitor
	return c
}

// Crypt sets the Crypt object to use for automatic encryption and decryption.
func (c *Count) Crypt(crypt *driver.Crypt) *Count {
	if c == nil {
		c = new(Count)
	}

	c.crypt = crypt
	return c
}

// Database sets the database to run this operation against.
func (c *Count) Database(database string) *Count {
	if c == nil {
		c = new(Count)
	}

	c.database = database
	return c
}

// Deployment sets the deployment to use for this operation.
func (c *Count) Deployment(deployment driver.Deployment) *Count {
	if c == nil {
		c = new(Count)
	}

	c.deployment = deployment
	return c
}

// ReadConcern specifies the read concern for this operation.
func (c *Count) ReadConcern(readConcern *readconcern.ReadConcern) *Count {
	if c == nil {
		c = new(Count)
	}

	c.readConcern = readConcern
	return c
}

// ReadPreference set the read prefernce used with this operation.
func (c *Count) ReadPreference(readPreference *readpref.ReadPref) *Count {
	if c == nil {
		c = new(Count)
	}

	c.readPreference = readPreference
	return c
}

// ServerSelector sets the selector used to retrieve a server.
func (c *Count) ServerSelector(selector description.ServerSelector) *Count {
	if c == nil {
		c = new(Count)
	}

	c.selector = selector
	return c
}

// Retry enables retryable mode for this operation. Retries are handled automatically in driver.Operation.Execute based
// on how the operation is set.
func (c *Count) Retry(retry driver.RetryMode) *Count {
	if c == nil {
		c = new(Count)
	}

	c.retry = &retry
	return c
}
