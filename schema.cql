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

CREATE TABLE sunsets (
  url text,
  PRIMARY KEY (url)
) WITH
  bloom_filter_fp_chance=0.010000 AND
  caching='{"keys":"ALL", "rows_per_partition":"NONE"}' AND
  comment='test table for sunset videos' AND
  dclocal_read_repair_chance=0.100000 AND
  gc_grace_seconds=864000 AND
  read_repair_chance=0.000000 AND
  default_time_to_live=0 AND
  speculative_retry='99.0PERCENTILE' AND
  memtable_flush_period_in_ms=0 AND
  compaction={'class': 'SizeTieredCompactionStrategy'} AND
  compression={'sstable_compression': 'LZ4Compressor'};

 https://www.youtube.com/embed/pY54WU0C3i4
 https://www.youtube.com/embed/kr7MDoWLQ14
 https://www.youtube.com/embed/2od2GZg7-88