DROP TABLE IF EXISTS user;

CREATE TABLE user
(
	id BIGINT(20) NOT NULL COMMENT '����ID',
	name VARCHAR(30) NULL DEFAULT NULL COMMENT '����',
	age INT(11) NULL DEFAULT NULL COMMENT '����',
	email VARCHAR(50) NULL DEFAULT NULL COMMENT '����',
	PRIMARY KEY (id)
);