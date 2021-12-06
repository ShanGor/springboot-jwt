drop table if exists random_city;
CREATE TABLE random_city (
  id SERIAL primary key,
  name varchar(255) DEFAULT NULL
);
drop table if exists app_role;
CREATE TABLE app_role (
  id SERIAL primary key,
  description varchar(255) DEFAULT NULL,
  role_name varchar(255) DEFAULT NULL
);

drop table if exists app_user;
CREATE TABLE app_user (
  id SERIAL primary key,
  first_name varchar(255) NOT NULL,
  last_name varchar(255) NOT NULL,
  password varchar(255) NOT NULL,
  username varchar(255) NOT NULL
);

drop table if exists user_role;
CREATE TABLE user_role (
  user_id bigint NOT NULL,
  role_id bigint NOT NULL
);
