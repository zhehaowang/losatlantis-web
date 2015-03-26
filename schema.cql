/* 
 * What if someone registers on our site, and meanwhile tries to logon with openid 
 * So we want one entry keyed by email, and a list of openids?
 */

CREATE KEYSPACE losatlantis WITH replication = {
  'class': 'SimpleStrategy',
  'replication_factor': '3'
};

/**
 * We create jabber user and password automatically on profile register/first logon with OpenID
 * The jabber user name (JID) is inferred as [email (with '.' replacing '@') @ archive-dev.remap.ucla.edu]
 * The jabber password is the registration email, since it's not mandatory that they have
 * a site password, if they log on with OpenID. (Do we want to add a jabber password?)
 *
 * The idea is once a user logs in our site, he logs into jabber service automatically,
 * and that's 'supposedly' the only way the user's going to interact with Jabber.
 */

CREATE TABLE users (
  user_name varchar,
  email varchar,
  password varchar,
  openid list<varchar>,
  type int,
  PRIMARY KEY (email)
);