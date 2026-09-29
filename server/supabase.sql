create extension if not exists pgcrypto;

create table if not exists sessions (
  id uuid primary key default gen_random_uuid(),
  challenge_name text,
  source_type text check (source_type in ('source', 'binary', 'juice_shop', 'ctf_fixture')),
  created_at timestamptz default now()
);

create table if not exists messages (
  id uuid primary key default gen_random_uuid(),
  session_id uuid references sessions(id) on delete cascade,
  role text check (role in ('user', 'agent', 'tool')),
  content text,
  tool_name text,
  tool_result jsonb,
  created_at timestamptz default now()
);

create table if not exists runs (
  id uuid primary key default gen_random_uuid(),
  challenge_name text,
  vuln_class text,
  predicted_class text,
  correct boolean,
  loops_taken int,
  evidence text,
  created_at timestamptz default now()
);
