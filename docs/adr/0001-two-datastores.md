# ADR-0001: Two datastores for v1 (Postgres + NATS)

Status: accepted · Date: 2026-07-08

## Context
The v1 target is 50 endpoints and ~1k EPS on a single 16 GB host. The reflex EDR
stack (Kafka + Elasticsearch + Neo4j + S3 + Redis + Postgres) is six stateful
systems to operate for a load one box handles.

## Decision
Ship **two** stateful dependencies:
- **PostgreSQL** for events, detections, investigations, the provenance graph
  (adjacency tables + recursive CTEs), full-text search (GIN), and the
  hash-chained audit log.
- **NATS JetStream** for the durable ingest queue (single binary, embeddable).

Everything else sits behind a Go interface with a simple implementation first:
`EventStore`, `InvestigationStore`, `GraphStore`, `Search`, `ObjectStore`, `Bus`.

## Consequences
- One `docker compose up`; graph queries stay in Postgres until they don't.
- Scale-out is an interface swap, not a rewrite: graph→Neo4j, search→OpenSearch,
  bus→Kafka, blobs→S3/MinIO.
- Risk: recursive-CTE graph queries get expensive with deep retention. Mitigated
  by doing bounded traversal in app memory (see correlate/) and persisting only
  finished subgraphs. Failing signal: p95 `/investigations/{id}` latency rising
  with retention depth.

## Rejected
- Kafka: operational weight unjustified at 1k EPS.
- Neo4j day 1: a second datastore for a graph that fits in Postgres at this size.
- Elasticsearch: Postgres FTS covers v1 search needs.
