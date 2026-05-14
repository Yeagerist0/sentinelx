-- SentinelX v1 schema. Two datastores only (Postgres + NATS); the graph lives in
-- Postgres as adjacency tables queried with recursive CTEs — Neo4j is a
-- scale-out swap behind GraphStore, not a day-1 dependency (ADR-0001).

-- ---------- normalized event ----------
CREATE TYPE event_type AS ENUM (
  'process_start','process_stop','file_write','file_read',
  'net_connect','dns_query','module_load');

CREATE TABLE event (
  event_id        text PRIMARY KEY,
  host_id         text NOT NULL,
  ts              timestamptz NOT NULL,
  ingest_ts       timestamptz NOT NULL DEFAULT now(),
  type            event_type NOT NULL,
  proc_guid       text NOT NULL,          -- stable process key: hash(boot_id,pid,start_time)
  parent_guid     text,
  proc_image      text,
  proc_cmdline    text,
  obj_file_path   text,
  obj_net_raddr   inet,
  obj_net_rport   int,
  obj_dns_query   text,
  raw             jsonb NOT NULL,
  raw_hash        text NOT NULL
);
CREATE INDEX event_host_ts   ON event (host_id, ts);
CREATE INDEX event_proc      ON event (proc_guid);
CREATE INDEX event_parent    ON event (parent_guid);
CREATE INDEX event_raw_gin   ON event USING gin (raw);

-- ---------- provenance graph ----------
CREATE TYPE node_kind AS ENUM ('process','file','socket','dns','module');
CREATE TABLE graph_node (
  node_id     text PRIMARY KEY,
  host_id     text NOT NULL,
  kind        node_kind NOT NULL,
  label       text NOT NULL,
  degree_out  int NOT NULL DEFAULT 0,
  degree_in   int NOT NULL DEFAULT 0,
  is_hub      boolean NOT NULL DEFAULT false
);
CREATE TABLE graph_edge (
  edge_id   bigserial PRIMARY KEY,
  host_id   text NOT NULL,
  src       text NOT NULL REFERENCES graph_node(node_id),
  dst       text NOT NULL REFERENCES graph_node(node_id),
  rel       text NOT NULL,
  ts        timestamptz NOT NULL,
  event_id  text NOT NULL REFERENCES event(event_id),
  weight    real NOT NULL DEFAULT 0.5    -- rarity weight in [0.05,1.0]
);
CREATE INDEX graph_edge_src ON graph_edge (src, ts);
CREATE INDEX graph_edge_dst ON graph_edge (dst, ts);

-- ---------- detection ----------
CREATE TABLE detection (
  detection_id bigserial PRIMARY KEY,
  rule_id      text NOT NULL,
  rule_version text NOT NULL,
  host_id      text NOT NULL,
  proc_guid    text NOT NULL,
  event_ids    text[] NOT NULL,
  technique    text[] NOT NULL,
  severity     smallint NOT NULL,
  ts           timestamptz NOT NULL,
  dedup_key    text NOT NULL UNIQUE
);

-- ---------- investigation ----------
CREATE TYPE inv_status AS ENUM ('open','closed');
CREATE TABLE investigation (
  inv_id        bigserial PRIMARY KEY,
  host_id       text NOT NULL,
  root_guid     text NOT NULL,
  status        inv_status NOT NULL DEFAULT 'open',
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  risk_score    int NOT NULL DEFAULT 0,
  score_factors jsonb NOT NULL DEFAULT '[]',
  technique_set text[] NOT NULL DEFAULT '{}',
  summary       text,
  narrative     text
);
CREATE TABLE investigation_detection (inv_id bigint, detection_id bigint, PRIMARY KEY(inv_id,detection_id));
CREATE TABLE investigation_event     (inv_id bigint, event_id text,       PRIMARY KEY(inv_id,event_id));
CREATE TABLE investigation_edge      (inv_id bigint, edge_id bigint,      PRIMARY KEY(inv_id,edge_id));

-- ---------- tamper-evident audit ----------
CREATE TABLE audit_log (
  seq          bigserial PRIMARY KEY,
  ts           timestamptz NOT NULL DEFAULT now(),
  kind         text NOT NULL,
  ref          text NOT NULL,
  payload_hash text NOT NULL,
  prev_hash    text NOT NULL,
  this_hash    text NOT NULL
);
