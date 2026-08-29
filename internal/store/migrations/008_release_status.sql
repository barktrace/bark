ALTER TABLE releases ADD COLUMN status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'archived'));
