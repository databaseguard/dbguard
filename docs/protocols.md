# Database wire protocol notes

Source references: `internal/proto/postgres.go`, `internal/proto/mysql.go`,
`internal/proto/wire.go`. Kernel-side limits: `bpf/include/dbguard/common.h`.

## PostgreSQL frontend/backend protocol (v3)

After the StartupMessage (int32 length, int32 protocol 196608 = 3<<16,
NUL-separated key/value pairs), every message is:

    byte      type
    int32     length (includes itself, excludes the type byte)
    payload

Messages of interest, frontend direction:

    'Q' SimpleQuery   - SQL is the entire payload, NUL-terminated
    'P' Parse         - extended protocol: named prepared statement
    'B' Bind          - binds parameters to a Parse
    'E' Execute       - executes a bound portal
    'S' Sync          - transaction boundary of an extended batch
    'X' Terminate     - client closes the session

Where SQL lives: full text in `Q`; for extended protocol the statement
text is in `P` (parameters arrive separately in `B` - DBGuard matches the
prepared statement id to its text so `E` events inherit the SQL, with
parameter values unknown by design, never guessed).

Backend errors ('E' in server direction, disambiguated by stream state)
are used by the anomaly module for failed-auth streaks.

## MySQL client/server protocol

Command phase (after handshake/auth), each packet:

    int24_LE  payload length
    byte      sequence id
    byte      command
    payload

Commands of interest:

    COM_QUERY          0x03  - SQL text follows directly
    COM_STMT_PREPARE   0x16  - statement text; server returns a stmt id
    COM_STMT_EXECUTE   0x17  - executes a prepared stmt id
    COM_STMT_CLOSE     0x19  - frees a stmt id
    COM_QUIT           0x01

As with PostgreSQL, the parser keeps a stmt-id -> SQL map so prepared
executions are attributed to their text. Auth switch and SSL request
packets are parsed to mark the session encrypted (visibility ends there,
see docs/threat-model.md).

## Kernel heuristics vs user-space parser

The kernel program (`sqli_firewall.bpf.c`, `audit.bpf.c`) works on the
first `DBG_MAX_SQL` (512) bytes of the payload captured by cgroup_skb:

- cheap byte-pattern hints (OR/AND tautology, UNION SELECT, sleep calls),
- PII pre-scan flags: DBG_QF_LUHN_HIT (digit run passing Luhn),
  DBG_QF_SSN_LIKE, DBG_QF_SECRET_LIKE (entropy approximation), DBG_QF_DDL,
  DBG_QF_BULK_SELECT.

These hints are advisory: they rate-limit what must be inspected in
user-space and optionally gate in-kernel drop (`sqli.in_kernel_drop`).
The authoritative analysis is the user-space parser + detectors: full SQL
(`sqli.max_sql_len`, default 16 KiB), protocol state machines, parameter
attribution, PII detectors with real entropy, and policy regexes.

## Adding a new engine

1. **Wire parser.** Implement a parser in `internal/proto` returning
   `Message{SQL, User, Database}` structs; feed it from the pipeline when
   the session's server port matches (`ebpf.ports.*`).
2. **Engine detection by port.** Add the default port to `PortsConfig`
   (config schema already has `sqlite_port` for TCP front-ends such as
   litestream/steampipe) and map port -> engine in the pipeline.
3. **Kernel probes.** For embedded engines (SQLite has no wire protocol),
   use uprobes: `sqlite3_exec`, `sqlite3_prepare_v2/v3` are already listed
   in `ebpf.attach.sqlite_symbols`; add the engine enum (DBG_ENG_SQLITE
   exists in common.h) to decoding tables in `internal/ebpf/types.go`.
4. **Policy support.** Add the engine name to the `engines` matcher
   documentation and to validation in the policy engine.
5. **Tests.** Unit-test the parser against captured frame fixtures, then
   run `scripts/setup-dbs.sh` (SQLite file at /tmp/dbguard_test.db) and
   `scripts/demo.sh` adapted to the new client.
