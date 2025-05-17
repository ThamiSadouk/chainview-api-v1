CREATE SCHEMA IF NOT EXISTS chainview;

CREATE TABLE chainview.users (
   id UUID PRIMARY KEY,
   name TEXT NOT NULL,
   email TEXT NOT NULL UNIQUE,
   password TEXT NOT NULL,
   created_at TIMESTAMPTZ DEFAULT NOW()
);