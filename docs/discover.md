# Discover and dashboards

Open **Discover** at `/ui/discover/` to query retained errors, transactions,
spans, structured logs, and metrics. **Dashboards** at `/ui/dashboards/` save
those queries as table, number, bar, line, or area widgets.

## Query model

A query selects up to 20 fields across at most 500 projects and returns at most
100 rows over a maximum of 90 days. The default range is 24 hours. Supported
aggregates are:

```text
count() count(field) count_unique(field)
sum(field) avg(field) min(field) max(field)
p50(field) p75(field) p90(field) p95(field) p99(field)
```

Filters use `field:value`; prefix a filter with `-` to negate it, use `*` as a
wildcard, and quote text containing spaces:

```text
environment:production level:error "connection refused"
-release:canary-* transaction.op:http.server
```

Useful dataset fields include:

| Dataset | Fields |
| --- | --- |
| errors | `event.id`, `issue.id`, `project`, `title`, `level`, `status`, `environment`, `release`, `platform`, `timestamp` |
| transactions | `event.id`, `project`, `transaction`, `transaction.op`, `transaction.status`, `trace`, `duration`, `spans`, `environment`, `release`, `timestamp` |
| spans | `span.id`, `parent_span`, `trace`, `project`, `span.op`, `span.description`, `span.status`, `duration`, `timestamp` |
| logs | `sentry.item_id`, `project`, `message`, `severity`, `environment`, `release`, `trace`, `span.id`, `timestamp` |
| metrics | `project`, `metric.name`, `metric.type`, `metric.value`, `metric.unit`, `timestamp` |

Only selected fields can be used for ordering. Prefix the field with `-` for
descending order. Non-aggregate fields automatically become grouping keys when
an aggregate is selected.

## Native API

```sh
curl --get https://errors.example.com/discover \
  -H "Authorization: Bearer $BARKTRACE_API_TOKEN" \
  --data-urlencode organization_id=ORG_UUID \
  --data-urlencode dataset=transactions \
  --data-urlencode 'field=transaction' \
  --data-urlencode 'field=count()' \
  --data-urlencode 'field=p95(duration)' \
  --data-urlencode 'query=environment:production' \
  --data-urlencode stats_period=7d \
  --data-urlencode 'order_by=-p95(duration)'
```

The compatible endpoint `/api/0/organizations/{slug}/events/` accepts the same
parameters, including Sentry's `statsPeriod`, `per_page`, and `orderby` names.

Saved dashboards use these native endpoints:

```text
GET    /dashboards?organization_id={organization_id}
POST   /organizations/{organization_id}/dashboards
GET    /dashboards/{dashboard_id}
PATCH  /dashboards/{dashboard_id}
DELETE /dashboards/{dashboard_id}
POST   /dashboards/{dashboard_id}/widgets
PATCH  /dashboards/{dashboard_id}/widgets/{widget_id}
DELETE /dashboards/{dashboard_id}/widgets/{widget_id}
```

## Permissions

Organization members can query projects they can access and view saved
dashboards. A project-level `none` override excludes that project's rows.
Creating, editing, or deleting dashboards and widgets requires organization
administrator access; project-scoped dashboards additionally require effective
project administrator access. Successful mutations are recorded in the audit
log. MCP read/write scopes enforce the equivalent boundary for MCP clients.
