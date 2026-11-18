# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ARTEX is a self-hosted, LLM multi-agent autonomous penetration testing system: a Go monolith
(module `github.com/Autumn-27/artex`, Go 1.26) with a Next.js UI (`web/`) and PostgreSQL. This
repository is a fork of Autumn-27/ARTEX (AGPL-3.0); the module path keeps the upstream name.

## Commands

### Run

```bash
./dev.sh                                   # backend :8787 + traffic proxy :8788 + next dev :5173
go run ./cmd/artex -addr :8787 -proxy 127.0.0.1:8788   # backend only (UI not embedded)
cd web && npm run dev                      # frontend only; /api is proxied to :8787 (override: AUTOPENTEST_API)
cd web && NEXT_PUBLIC_MOCK=1 npm run dev   # UI on mock data, no backend (web/src/lib/mock)
```

The backend needs PostgreSQL: `ARTEX_PG_DSN`, or `config.json` (see `config.example.json`). It
creates the database, applies the schema and seeds itself on startup.

### Build

```bash
# single binary with the UI embedded (only -tags embedui embeds it)
cd web && npm ci && npm run build:static && cd ..
cp -r web/out server/webui/dist
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex

./build.sh                    # same, for the current OS/arch, into dist/
./build.sh --release          # all release targets, zipped
docker compose build          # image is built locally; there is no registry tag
```

### Checks (what CI runs, `.github/workflows/ci.yml`)

```bash
# Go
gofmt -l $(git ls-files '*.go')            # must print nothing
go build ./... && go vet ./...
ARTEX_PG_DSN='postgres://artex:testpass@localhost:5432/artextest?sslmode=disable' go test -p 1 ./...
go test -race -p 1 ./agent ./server ./db ./traffic/...   # CI runs -race on a fixed package list, with its own database

# one test
go test ./agent -run TestName
go test ./server -run 'TestName/subtest' -v

# Web (in web/)
npx tsc --noEmit
npm run test:polling && npm run test:replay   # node --test
npm run build:static
npm run check                                 # biome lint + format (also run by the husky pre-commit via lint-staged)

# Shell and Python
shellcheck -S warning install.sh update.sh start.sh scripts/backup.sh reset-password.sh scripts/*.sh .github/scripts/bot.sh
bash scripts/test-extract-changelog-section.sh && bash scripts/test-bot-context.sh
python3 scripts/posture_check_test.py
```

Go test notes:

- Most `db`, `server`, `agent`, `evidence` and `llmrec` tests need Postgres and **skip silently**
  when `ARTEX_PG_DSN` is unset or unreachable. A green run without a database proves little.
- Each package's `TestMain` calls `db.SuffixTestDatabase`, so `ARTEX_PG_DSN=.../artextest` becomes
  `artextest_agent`, `artextest_server`, and so on; the databases are created automatically.
- CI uses `-p 1`. The db tests are not idempotent across runs on the same database (the race job
  uses a separate one for that reason).
- A few tests skip themselves in code with a pointer to issue #9; do not re-enable or add skips
  to get green.

## Architecture

`README.md` ("How it works", "Architecture") has the diagrams. The parts that span files:

**Dual graphs.** State lives in two PostgreSQL graphs linked by anchors:

- *Asset graph*, shared across tasks: `root_domain / subdomain / ip / service / app / endpoint`,
  owned by companies. Parent links and dedup keys are computed by code; agents only submit raw
  observations.
- *Exploration graph*, per task: `goal / intent / fact / finding / hint` nodes with
  `spawns / derived_from / yields / proves` edges.
- `exploration_anchors(node_id, asset_id)` ties the two together and drives coverage.

**Engine loop** (`server/engine*.go`, `server/manager.go`). `Manager` owns tasks, engines and
stores. Each task has one planner loop and N worker goroutines. Any graph change wakes the planner
(debounced); the planner is the only producer of intents and usually dispatches none; a worker
claims one intent, runs real tools, writes facts/assets/findings back, and stops. The write-back
wakes the planner again until `prove_goal` closes the task.

**Agents** (`agent/`). Built on the external `norma` SDK (`agentcore`, `tool`, `permission`,
`harness`, `memory`, `transcript`). Roles: `goals` (goal decomposition and scope), `planner`,
`worker`, `mainagent` (human-in-the-loop chat), `retester`. `ToolSet` (`agent/tools*.go`) exposes
the graphs to the LLM as tools. Prompts are versioned rows in `agent_prompts`; some prompt tails
are appended by code and are not editable.

**Supporting packages.**

| Package | Role |
| --- | --- |
| `server` | `net/http` REST under `/api/*`, JWT auth, SSE; also the engine |
| `db` | pgx persistence, embedded `schema.sql` and migrations, at-rest encryption of secrets |
| `traffic` | recording MITM proxy (:8788), replay, pacing; `traffic/rewrite` is the pure rewrite-rule engine |
| `guard`, `intercept` | tool approval gate, target gate, pinned dialer |
| `egress` | noise-profile governor for ARTEX's own requests to targets |
| `enrich` | async DNS/HTTP enrichment of assets |
| `evidence`, `report` | finding evidence snapshots and the report/export |
| `llmpool`, `llmrec` | LLM provider profiles/failover and call recording |
| `mcphttp`, `notify`, `sidequestion` | MCP over HTTP, notifications, side questions |
| `skills/` | agent skills, one directory per skill with a `SKILL.md`; mounted into the container at runtime |
| `extension/` | browser extension that captures traffic |

**Frontend** (`web/`). Next.js 16 App Router, React 19, Tailwind 4, shadcn/ui, zustand, Biome.
Routes live in `web/src/app/(main)/{dashboard,chat,function,system}`. All backend calls go through
`web/src/lib/api.ts`, which short-circuits to `web/src/lib/mock` when `NEXT_PUBLIC_MOCK=1`; a new
endpoint needs its mock kept in step. The release build is a static export
(`NEXT_EXPORT=1`, output `web/out`) copied to `server/webui/dist` and embedded by
`server/webui_embed.go`; without the `embedui` tag `server/webui_stub.go` serves a 404.

## Rules specific to this repository

- **Schema changes** go in a new `db/migrations/NNNN_slug.sql`. `db/schema.sql` is the idempotent
  base executed on every startup. Never edit a published migration: `Open` checks each applied
  migration's SHA-256 and refuses to start on a mismatch. Fix forward.
- **`RSI.md` is a contract.** The adversarial and quality gates, scope and authorization checks,
  prompt-injection defenses (untrusted-output boundary, nonce envelope), tool allowlists and the
  code-owned prompt tails are never in the search space of any automated harness edit. Prompt
  changes are new `agent_prompts` versions and need owner approval.
- **Tool output is untrusted data.** Target- and agent-derived text reaches models inside
  code-owned envelopes (`agent/untrusted_*.go`, `agent/data_envelope.go`); keep new tool results
  and prompt fields inside them.
- **Outbound requests to targets** go through the target gate and the egress governor
  (`intercept.PinnedDialer`, `egress`), not a bare `http.Client`.
- **Secrets at rest** (LLM keys, MCP env, credentials, rewrite-rule matchers/actions, evidence
  snapshots) are AES-256-GCM encrypted with `keys/secret.key` or `ARTEX_SECRET_KEY`; new secret
  columns follow the same path.
- **`CHANGELOG.md`** follows Keep a Changelog; user-visible changes get an entry under
  `[Unreleased]` with the PR number. Release notes are extracted from it
  (`scripts/extract-changelog-section.sh`).
- **Commits** use conventional prefixes with a package scope: `feat(server): …`, `fix(db): …`,
  `ci: …`, `docs: …`.
- New features are generally **off by default** behind an `ARTEX_*` environment variable or a
  setting, documented in `README.md` "Configuration", `.env.example` and `docker-compose.yml`.

## Git and GitHub conventions

These rules override any default attribution or branch naming.

- **Commit messages:** no `Co-Authored-By: Claude ...` or `Claude-Session: ...`
  trailers, and no other AI attribution line.
- **Pull request descriptions:** no "Generated with Claude Code" footer and no
  session link.
- **Branch names:** `feature/<topic>` for new features, `bugfix/<topic>` for
  fixes. Never `claude/...`.

## Further reading

- `docs/traffic-rewrite-rules.md`, `docs/vulnerability-traffic-evidence.md`, `docs/rsi-lessons.md`
- `scripts/benchmark/README.md` (benchmark runner), `scripts/sql/README.md` (online index scripts)
- `SECURITY.md`
