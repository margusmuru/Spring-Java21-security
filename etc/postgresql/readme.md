# PostgreSQL Demo Database
run
```bash
docker compose up -d
```


Using publich schema of demo_db 

# Users

## Create table users
```postgresql
create  table users (
    id integer primary key,
    username text,
    password text
);
```
## Add data 
```postgresql
insert into users values (1, 'admin', 'password');
insert into users values (2, 'user', 'pass');
```

## Create table refresh_tokens
```postgresql
CREATE TABLE refresh_token (
   id SERIAL PRIMARY KEY,
   user_id integer,
   token_hash VARCHAR(512),
   expiry_date TIMESTAMP,
   created TIMESTAMP
);

CREATE UNIQUE INDEX idx_refresh_tokens_token_hash ON refresh_token(token_hash);

```