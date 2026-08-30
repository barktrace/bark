ALTER TABLE alert_deliveries ADD COLUMN destination_type TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_deliveries ADD COLUMN destination_url TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_deliveries ADD COLUMN destination_email TEXT NOT NULL DEFAULT '';

CREATE TABLE alert_rule_actions (
    rule_id TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    destination_type TEXT NOT NULL CHECK (destination_type IN ('webhook', 'slack', 'email')),
    destination_url TEXT NOT NULL DEFAULT '',
    destination_email TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(rule_id, position)
);

INSERT INTO alert_rule_actions(rule_id, position, destination_type, destination_url, destination_email)
SELECT id, 0, destination_type, destination_url, destination_email FROM alert_rules;
