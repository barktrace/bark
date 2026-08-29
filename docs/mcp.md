# MCP server

Barktrace includes a stateless Streamable HTTP Model Context Protocol endpoint in
the main process. It requires no sidecar. Organization administrators create
scoped credentials from the dashboard; the legacy instance-wide environment
token remains available for upgrades and recovery.

## Enable it

Sign in as an organization administrator, open **Organization**, and create an
MCP token with `read` or `read` + `write` scope. The secret is displayed once.
For a legacy instance-wide credential, generate a token and store it in your
deployment's secret manager:

```sh
openssl rand -hex 32
```

Set the result as `BARKTRACE_MCP_TOKEN` and redeploy. In either mode the endpoint is:

```text
https://errors.example.com/mcp
```

Clients must send `Authorization: Bearer <token>`. Browser-origin requests are
accepted only from `BARKTRACE_PUBLIC_URL`. The supported protocol versions are
`2025-11-25`, `2025-06-18`, and `2025-03-26`.

## Generic client configuration

MCP clients use different configuration wrappers, but the transport values are
the same:

```json
{
  "mcpServers": {
    "barktrace": {
      "type": "http",
      "url": "https://errors.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${BARKTRACE_MCP_TOKEN}"
      }
    }
  }
}
```

If a client does not expand environment variables inside headers, use its
secret or bearer-token setting rather than writing the token into a tracked
configuration file.

You can verify discovery directly:

```sh
curl --fail-with-body https://errors.example.com/mcp \
  -H "Authorization: Bearer $BARKTRACE_MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## Available tools

| Tool | Effect |
| --- | --- |
| `list_organizations` | Lists organizations visible to the credential and their project/issue counts. |
| `list_projects` | Lists projects and DSNs, optionally by organization slug. |
| `get_project_summary` | Returns issue, open issue, event, and release counts. |
| `list_issues` | Searches and filters grouped issues for a project. |
| `get_issue` | Returns an issue and its release linkage. |
| `update_issue_status` | Sets an issue to unresolved, resolved, or ignored. |
| `list_events` | Lists event occurrences, optionally for one issue. |
| `get_event` | Returns an event including its original Sentry JSON. |
| `list_releases` | Lists project releases and event counts. |
| `list_transactions`, `list_logs` | Queries performance data and structured logs. |
| `list_uptime_monitors`, `list_uptime_checks` | Inspects uptime status and history. |
| `list_cron_monitors`, `list_cron_checkins` | Inspects scheduled-job health. |
| `list_feedback`, `list_attachments` | Inspects user reports and event attachments. |
| `list_replays`, `list_profiles`, `list_metrics` | Inspects extended telemetry products. |
| `list_alert_rules`, `list_alert_deliveries` | Inspects alert configuration and delivery. |
| `list_artifacts` | Lists source maps and debug files. |
| `list_deploys`, `list_commits`, `list_suspect_commits` | Correlates releases and source changes. |
| `list_project_quotas`, `list_ingestion_jobs` | Inspects limits, retries, and dead letters. |
| `get_storage_summary`, `list_audit_logs` | Inspects tenant storage and security activity. |

## Security boundary

Database-backed MCP tokens can access only their organization. `read` tokens
cannot invoke mutation tools; `write` tokens can also update issue status, and
successful mutations are recorded with actor type `mcp`. Treat every token as a
secret and use HTTPS. `BARKTRACE_MCP_TOKEN`, when configured, deliberately keeps
legacy instance-wide administrative access and should be reserved for recovery.
