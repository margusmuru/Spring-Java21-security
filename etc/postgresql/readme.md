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
