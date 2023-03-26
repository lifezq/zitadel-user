create table users
(
    id      int AUTO_INCREMENT primary key,
    name    varchar(50) NOT NULL,
    address varchar(100),
    age     int         NOT NULL DEFAULT 0,
    gender  varchar(10) NOT NULL,
    salary  double,
    created DATETIME             DEFAULT CURRENT_TIMESTAMP()
);