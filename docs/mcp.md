# MCP server

Barktrace includes a stateless Streamable HTTP Model Context Protocol endpoint in
the main process. It requires no sidecar and is disabled unless
`BARKTRACE_MCP_TOKEN` is configured.

## Enable it

Generate a dedicated administrative token and store it in your deployment's
secret manager:

```sh
openssl rand -hex 32
```

Set the result as `BARKTRACE_MCP_TOKEN` and redeploy. The endpoint is then:

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
| `list_organizations` | Lists all organizations and their project/issue counts. |
| `list_projects` | Lists projects and DSNs, optionally by organization slug. |
| `get_project_summary` | Returns issue, open issue, event, and release counts. |
| `list_issues` | Searches and filters grouped issues for a project. |
| `get_issue` | Returns an issue and its release linkage. |
| `update_issue_status` | Sets an issue to unresolved, resolved, or ignored. |
| `list_events` | Lists event occurrences, optionally for one issue. |
| `get_event` | Returns an event including its original Sentry JSON. |
| `list_releases` | Lists project releases and event counts. |

## Security boundary

The MCP token is currently instance-wide. It can read every organization and
raw event payload, and it can change issue status. Treat it as an administrative
secret, use HTTPS, do not reuse the OIDC client secret, and rotate it by changing
the environment variable and redeploying. Per-user OAuth, organization-scoped
tokens, and an MCP audit log are future hardening work.
