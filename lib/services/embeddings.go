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

package services

import (
	"context"
	"time"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	embeddingpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/embedding/v1"
	"github.com/gravitational/teleport/api/internalutils/stream"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/retryutils"
	"github.com/gravitational/teleport/lib/ai"
)

// Embeddings service is responsible for storing and retrieving embeddings in
// the backend. The backend acts as an embedding cache. Embeddings can be
// re-generated by an ai.Embedder.
type Embeddings interface {
	// GetEmbedding looks up a single embedding by its name in the backend.
	GetEmbedding(ctx context.Context, kind, resourceID string) (*ai.Embedding, error)
	// GetEmbeddings returns all embeddings for a given kind.
	GetEmbeddings(ctx context.Context, kind string) stream.Stream[*ai.Embedding]
	// UpsertEmbedding creates or update a single ai.Embedding in the backend.
	UpsertEmbedding(ctx context.Context, embedding *ai.Embedding) (*ai.Embedding, error)
}

// MarshalEmbedding marshals the ai.Embedding resource to binary ProtoBuf.
func MarshalEmbedding(embedding *ai.Embedding) ([]byte, error) {
	data, err := proto.Marshal((*embeddingpb.Embedding)(embedding))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return data, nil
}

// UnmarshalEmbedding unmarshals binary ProtoBuf into an ai.Embedding resource.
func UnmarshalEmbedding(bytes []byte) (*ai.Embedding, error) {
	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing embedding data")
	}
	var embedding embeddingpb.Embedding
	err := proto.Unmarshal(bytes, &embedding)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return (*ai.Embedding)(&embedding), nil
}

func EmbeddingHashMatches(embedding *ai.Embedding, hash ai.Sha256Hash) bool {
	if len(embedding.EmbeddedHash) != 32 {
		return false
	}

	return *(*ai.Sha256Hash)(embedding.EmbeddedHash) == hash
}

// serializeNode converts a type.Server into text ready to be fed to an
// embedding model. The YAML serialization function was chosen over JSON and
// CSV as it provided better results.
func serializeNode(node types.Server) ([]byte, error) {
	a := struct {
		Name    string            `yaml:"name"`
		Kind    string            `yaml:"kind"`
		SubKind string            `yaml:"subkind"`
		Labels  map[string]string `yaml:"labels"`
	}{
		Name:    node.GetName(),
		Kind:    types.KindNode,
		SubKind: node.GetSubKind(),
		Labels:  node.GetAllLabels(),
	}
	text, err := yaml.Marshal(&a)
	return text, trace.Wrap(err)
}

type batchReducer[T, V any] struct {
	data      []T
	batchSize int
	processFn func(ctx context.Context, data []T) (V, error)
}

func (b *batchReducer[T, V]) Add(ctx context.Context, data T) (V, error) {
	b.data = append(b.data, data)
	if len(b.data) >= b.batchSize {
		val, err := b.processFn(ctx, b.data)
		b.data = b.data[:0]
		return val, err
	}

	var def V
	return def, nil
}

func (b *batchReducer[T, V]) Finalize(ctx context.Context) (V, error) {
	if len(b.data) > 0 {
		val, err := b.processFn(ctx, b.data)
		b.data = b.data[:0]
		return val, err
	}

	var def V
	return def, nil
}

type EmbeddingProcessorConfig struct {
	AiClient     ai.Embedder
	EmbeddingSrv Embeddings
	NodeSrv      NodesStreamGetter
	Log          logrus.FieldLogger
	Jitter       retryutils.Jitter
}

type EmbeddingProcessor struct {
	aiClient     ai.Embedder
	embeddingSrv Embeddings
	nodeSrv      NodesStreamGetter
	log          logrus.FieldLogger
	jitter       retryutils.Jitter
}

func NewEmbeddingProcessor(cfg *EmbeddingProcessorConfig) *EmbeddingProcessor {
	return &EmbeddingProcessor{
		aiClient:     cfg.AiClient,
		embeddingSrv: cfg.EmbeddingSrv,
		nodeSrv:      cfg.NodeSrv,
		log:          cfg.Log,
		jitter:       cfg.Jitter,
	}
}

type nodeStringPair struct {
	node types.Server
	data string
}

func (e *EmbeddingProcessor) mapProcessFn(ctx context.Context, data []*nodeStringPair) ([]*ai.Embedding, error) {
	dataBatch := make([]string, 0, len(data))
	for _, pair := range data {
		dataBatch = append(dataBatch, pair.data)
	}

	embeddings, err := e.aiClient.ComputeEmbeddings(ctx, dataBatch)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	results := make([]*ai.Embedding, 0, len(embeddings))
	for i, embedding := range embeddings {
		emb := ai.NewEmbedding(types.KindNode,
			data[i].node.GetName(), embedding,
			ai.EmbeddingHash([]byte(data[i].data)),
		)
		results = append(results, emb)
	}

	return results, nil
}

func (e *EmbeddingProcessor) Run(ctx context.Context, period time.Duration) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.jitter(period)):
			e.process(ctx)
		}
	}
}

func (e *EmbeddingProcessor) process(ctx context.Context) {
	batch := &batchReducer[*nodeStringPair, []*ai.Embedding]{
		data:      make([]*nodeStringPair, 0),
		batchSize: 1000, // Max batch size allowed by OpenAI API
		processFn: e.mapProcessFn,
	}

	embeddingsStream := e.embeddingSrv.GetEmbeddings(ctx, "nodes")
	nodesStream := e.nodeSrv.GetNodeStream(ctx, "default")

	moveEmbeddingIter := true
	for {
		hasNextNode := nodesStream.Next()
		if !hasNextNode {
			break
		}

		embedding := &ai.Embedding{}
		hasNextEmbedding := embeddingsStream.Next()
		if hasNextEmbedding && moveEmbeddingIter {
			// Check if the embedding is for the current node
			// If exists, use it
			embedding = embeddingsStream.Item()
		}

		node := nodesStream.Item()

		nodeData, err := serializeNode(node)
		if err != nil {
			e.log.Errorf("Failed to serialize node: %v", err)
			continue
		}

		nodeHash := ai.EmbeddingHash(nodeData)
		if !EmbeddingHashMatches(embedding, nodeHash) {
			vectors, err := batch.Add(ctx, &nodeStringPair{node, string(nodeData)})
			if err != nil {
				e.log.Warnf("Failed to add node to batch: %v", err)

				// If something went wrong, stop processing the stream
				// and try again later
				break
			}

			if err := e.upsertEmbeddings(ctx, vectors); err != nil {
				e.log.Warnf("Failed to upsert embeddings: %v", err)
			}
		} else {
			moveEmbeddingIter = true
		}
	}

	err := trace.NewAggregate(embeddingsStream.Done(), embeddingsStream.Done())
	if err != nil {
		e.log.Warnf("Failed to precess embeddings stream: %v", err)
	}

	vectors, err := batch.Finalize(ctx)
	if err != nil {
		e.log.Warnf("Failed to add node to batch: %v", err)

		return
	}

	if err := e.upsertEmbeddings(ctx, vectors); err != nil {
		e.log.Warnf("Failed to upsert embeddings: %v", err)
	}
}

func (e *EmbeddingProcessor) upsertEmbeddings(ctx context.Context, rawEmbeddings []*ai.Embedding) error {
	// Store the new embeddings into the backend
	for _, embedding := range rawEmbeddings {
		_, err := e.embeddingSrv.UpsertEmbedding(ctx, embedding)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}
