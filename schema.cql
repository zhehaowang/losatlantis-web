/**
 * Based on Jeff's proposed schema
 */

/**
 * Using NetworkTopologyStrategy for plans of deploying in multiple data centers;
 * Replication factor of 2 tries to store two copies of each row, each copy in a different node.
 */
CREATE KEYSPACE losatlantis WITH replication = {
  'class': 'NetworkTopologyStrategy',
  'replication_factor': '2'
};

/**
 * Current types of participants in show_id to text mapping:
 * Watcher, tourist, traveler, citizen, guide, observator, crew, admin
 *
 * Question:
 * 1. Do we collect email?
 */
CREATE TABLE participant (
  username        text,
  role            map<int, text>,
  upload_count    int,
  uploaded_tags   set<text>,
  applied_tags    set<text>,
  logins          map<timestamp, text>
);
// Other lists we need per user? 
// Do we need any information on mobile/we client here? 

/**
 * Show table holds all global information per show
 * 
 * Show types include:
 * Rehearsal, preview, performance, test
 *
 * Statuses include:
 * Upcoming, current, past
 *
 * Global state is a more detailed representation of the current status of given show? Including:
 * act, scene, ritual
 *
 * Questions:
 * 1. Users, Characters, Crew and Watcher maps 'username' to 'role' in this show -> participant
 *    Would it be better to combine them into one column 
 * 
 * 2. Would it make more sense to move 'likes' and 'follows' to participant table?
 *    e.g. participants (likes, set<text>)? Placing these here meaning a participant likes another in this specific show?
 */
CREATE TABLE show (
  id              int,
  type            text,
  start_scheduled timestamp,
  start_actual    timestamp,
  end_actual      timestamp,
  status          text,
  global_state    map<text, text>,
  
  users           map<text, text>, 
  characters      set<text>,
  crew            set<text>,
  watchers        map<text, text>,
  
  tags            set<text>,
  
  likes           map<text, text>,     // username, media 
  follows         map<text, text>      // username, username (do we need this?) 
);

/**
 * Media table holds all media links plus our own metadata
 *
 * Question: 
 * 1. make sense for media to contain uploaded_time timestamp?
 *
 * Test:
 * 1. Tags querying (performance for set operation)?
 * 2. There's something mentioning Watchers vote on 1/D, we'll not incorporate that into the DB for now?
 */
CREATE TABLE media (
  key             text,
  tags            set<text>,
  approved        boolean,
  uploaded_by     text,
  in_show         set<int>
);

/**
 * Question:
 * 1. Do we need hyponyms as well as hypernyms for being bi-directional queryable?
 * 2. Same as above, separate character from user?
 * 3. A tag's relationship to a character and user is show_id specific?
 */
CREATE TABLE folksonomy (
// Tags, our primary way of making conceptual connections across domains
// Need to check wordnet structure
  tag             text                // tag in final format for show, lower case, normalized, etc. 
  original        text                // as originally supplied
  synset          set<text>           // wordnet synset (is this int)
  hypernym        set<text>           // hypernyms (only 1?) 
  
  characters      map<int, text>      // show_id, username
  users           map<int, text>      // show_id, username
  media           set<text>            // Not show_id specific? 
);

/**
 * Question:
 * 1. Similar question as above: combine dialogue, etc into the name of the params name/value pair?
 */
CREATE TABLE eventlog (
  // Running, high-granularity list of events.  Can use this to make decisions for media selection

  // required per event
  world_clock     timestamp
  name            text                // Need to work on namespace
  type            text                
  show_id         int 
  show_clock      timestamp           // can be negative if before the event. 
  generator       text                // what node or process generated the event

  // optional per event
  act             text                // if available, show related mappings
  scene           text       
  ritual          text      
  dialogue        text                // is there associated dialogue
  params          map<text, text>     // name / value pairs from time of event
  media           set<text>
  tags            set<text>
  characters      set<text>
  participants    set<text>
);

/**
 * Zhehao's debug schema
 */

/** 
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