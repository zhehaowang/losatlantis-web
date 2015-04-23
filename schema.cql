// LOS ATLANTIS Database Schema / Show Memory

/**
 * Using NetworkTopologyStrategy for plans of deploying in multiple data centers;
 * Replication factor of 2 tries to store two copies of each row, each copy in a different node.
 * zhehao: we are storing 2 copies of each row in ‘dc1’ and ‘dc2’, two arbitrary datacenter names.
 */
CREATE KEYSPACE IF NOT EXISTS LosAtlantis WITH replication = {
  'class': 'NetworkTopologyStrategy',
  'dc1': 2,
  'dc2': 2
};

use LosAtlantis;

// Can we simplify using user defined types? 

CREATE TABLE IF NOT EXISTS participant (
  username        text,
  email           text,

  //  show_id to text is watcher, tourist,  traveler, citizen, guide, observator, crew, admin 
  role            map<int, text>,
  
  // rest of Zhehao's fields go here. 
  upload_count    int,
  uploaded_tags   set<text>,
  applied_tags    set<text>,
  logins          map<timestamp, text>, // store a list of logins... 
  
  PRIMARY KEY (email)
);

// Other lists we need per user? 
// Do we need any information on mobile/we client here? 

/**
 * Holds all global information per show
 *
 * Zhehao:
 *
 * Questions:
 * 1. Users, Characters, Crew and Watcher maps 'username' to 'role' in this show -> participant
 *    Would it be better to combine them into one column 
 * 
 * 2. Would it make more sense to move 'likes' and 'follows' to participant table?
 *    e.g. participants (likes, set<text>)? Placing these here meaning a participant likes another in this specific show?
 */
CREATE TABLE IF NOT EXISTS show (
  id              int,
  type            text,                // rehearsal, preview, performance, test           
  start_scheduled timestamp,
  start_actual    timestamp,
  end_actual      timestamp,
  status          text,                // text is upcoming, current, past 
  users           map<text, text>,     // username, role 
  characters      set<text>,           // username
  crew            set<text>,           // username
  global_state    map<text, text>,     // act, scene, ritual, etc - other some what slowly-changing things 
  tags            set<text>,           // all tags that appear in show
  watchers        map<text, text>,     // username, username   (watcher: watchee) 
  likes           map<text, text>,     // username, media 
  follows         map<text, text>,     // username, username (do we need this?) 
  rituals         map<text, text>,     // ritual name/number, username - is this ok for dynamic updates? 
  
  PRIMARY KEY (id)
);

/**
 * Holds all media links plus our own metadata
 */
CREATE TABLE IF NOT EXISTS media (
  key             text,                // e.g., youtube video key?
  tags            set<text>,
  approved        boolean,
  uploaded_by     text,                // username
  in_show         set<int>,            // which shows use this?  (when should be in EVENT) 
  
  PRIMARY KEY (key)
);

/**
 * Tags, our primary way of making conceptual connections across domains
 * Need to check wordnet structure
 *
 * zhehao: 
 *   'order' seems to be a reserved name, changed to 'ring_order'
 */
CREATE TABLE IF NOT EXISTS folksonomy (
  tag             text,                // tag in final format for show, lower case, normalized, etc.  
  tag_capitalized text,                // with capitalization preserved
  type            text,                // category of tag (used for visualization - must match ring name to visualize)
  ring_order      float,               // order on the ring, application defined, we use [0...360] in this app to place on the ring
  granularity     float,               // from 0, very general ("object") to 1, very specific ("ZhehaoWang")
  language        text,                // blank = american english
  closest_english text,                // if language != american english
  original        text,                // as originally supplied
  synset          set<text>,           // wordnet synset (is this int)
  hypernym        set<text>,           // hypernyms (only 1?) 
  characters      map<int, text>,      // show_id, username
  participants    map<int, text>,      // show_id, username
  media           set<text>,           // Media key. Not show_id specific?   *If empty, should not be active in the piece* 
  
  PRIMARY KEY (tag)
);

/**
 * Running, high-granularity list of events.  
 * Can use this to make decisions for media selection
 *
 * zhehao:
 * Added timeuuid for primary key, should be different from world_clock, 
 * since the latter may follow a different pattern, or have a different granularity
 */
CREATE TABLE IF NOT EXISTS events_log (
  eventid         timeuuid,
  
  // required per event
  world_clock     timestamp,
  name            text,                // Need to work on namespace
  type            text,                
  show_id         int, 
  show_clock      timestamp,           // can be negative if before the event. 
  generator       text,                // what node or process generated the event

  // optional per event
  act             text,                // if available, show related mappings
  scene           text,       
  ritual          text,      
  dialogue        text,                // is there associated dialogue
  params          map<text, text>,     // name / value pairs from time of event
  media           set<text>,
  tags            set<text>,
  characters      set<text>,
  participants    set<text>,

  PRIMARY KEY (eventid)
);