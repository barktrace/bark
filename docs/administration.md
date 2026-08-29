# Administration

The Organization dashboard contains the controls described below. Owners and
administrators can manage members, retention, project alerts, and projects.

## Members and SSO invitations

Invite a teammate by email and choose `viewer`, `member`, or `admin`. If the
email already belongs to a Barktrace user, membership is granted immediately.
Otherwise the invitation stays pending for seven days and is accepted
automatically when that verified email signs in through OIDC. There is no
password or invitation-link login path.

## API tokens

Any member can create a personal token scoped to one organization. Tokens start
with `bark_`, are shown once, and work as `Authorization: Bearer <token>` on the
authenticated API. Expiry is optional. Revoking organization membership also
makes its tokens unusable.

## Alerts

Alert rules belong to a project and support `new_issue`, `regression`, and
`uptime_down` triggers. Destinations must be HTTPS webhook or Slack incoming
webhook URLs. The in-process worker retries failures three times; recent
delivery status is shown in the dashboard.

## Issue sharing and discard

Project administrators can enable a stable public link for an issue through
the Sentry-compatible issue update endpoint. The unauthenticated shared view
contains the issue and a sanitized latest event: user, request, contexts, SDK,
and package data are omitted. Shared responses are marked `no-store` and
`noindex`; disabling sharing immediately revokes the link.

Project administrators can also discard an issue. This deletes the issue and
its events and stores a project-scoped fingerprint tombstone. Future matching
events are acknowledged without storage and recorded as filtered ingestion
outcomes. Sharing changes and discards are retained in the organization audit
log. Discard is permanent unless an operator removes the corresponding
fingerprint tombstone directly from the database.

## Retention and cleanup

Each organization has a retention period from 1 to 3650 days, defaulting to 30.
The process runs cleanup six-hourly for events, transactions, spans, logs,
sessions, and uptime checks. Organization administrators can preview or run the
same cleanup from the dashboard. Backups remain the operator's responsibility.
