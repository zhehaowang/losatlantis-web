# losatlantis-web

The website that covers basic functions in Los Atlantis

## Usage

The proof-of-concept site is now online [here](http://archive-dev.remap.ucla.edu:5004).

1. By clicking "sign in", you should be directed to a page with federated login, login with account on our site, or register function.

2. For a quick test, you can try logging in with your Google account (tested with Google and stackexchange), or use existing accounts "watcher@watcher", "tourist@tourist" or "admin@admin", all with password "123".

3. Upon signing in, you should be able to modify your user name and user category by clicking "profile"; or join chat by clicking "chat".

4. When entering "chat", 
  * Watchers (such as "watcher@watcher" account) join a chatroom "observatory@conference.archive-dev.remap.ucla.edu" by default, and received messages are displayed in the textarea.
  * Tourists (such as "tourist@tourist") receive messages directed at "email(replace '@' with '.')@archive-dev.remap.ucla.edu" (such as tourist.tourist@archive-dev.remap.ucla.edu)
  * Crews (such as "admin@admin") have additional boxes for sending texts to any chatroom or user; For groupchat, please try with type "groupchat", and join the intended chatroom (which looks like "XXX@conference.archive-dev.remap.ucla.edu") before sending the message; For chatting to a certain user, please put the user's account (which looks like "XXX@archive-dev.remap.ucla.edu").
5. Alternatively, the active script has basic web components to test "chat": they are underlined and marked by colored text, and can be located by searching for "observatory:" or "The guide:"; upon clicking, the observatory component sends a "hello" message to the observatory chatroom that the watchers are in; while the guide component sends a "hello, [user name]" to every registered user.

## Python Package Dependencies

* Flask
* Flask-openid
* Flask-oidc
* Cassandra-driver (which requires six >= 1.6, an installation of another version of six in another directory may mess up)
* xmpppy

# Ejabberd setup configuration

* Enable Ejabberd's http-bind
* Allow in-band registration
* May want to set registration limitation on the same IP address to infinity