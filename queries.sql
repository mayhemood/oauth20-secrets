CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
);

CREATE TABLE secrets (
  id SERIAL PRIMARY KEY,
  secret TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id)
);