// TODO: Figuring out what the number after the jid means

function onConnect(status)
{
    if (status == Strophe.Status.CONNECTING) {
        console.log('Strophe is connecting.');
    } else if (status == Strophe.Status.CONNFAIL) {
        console.log('Strophe failed to connect.');
    } else if (status == Strophe.Status.DISCONNECTING) {
        console.log('Strophe is disconnecting.');
    } else if (status == Strophe.Status.DISCONNECTED) {
        console.log('Strophe is disconnected.');
    } else if (status == Strophe.Status.CONNECTED) {
        console.log('Strophe is connected.');
        
        // Add handlers for connection
        connection.addHandler(onMessage, null, 'message', null, null,  null); 
        // TODO: test if the following line's working as intended:
        //connection.addHandler(on_roster_change, "jabber:iq:roster", "iq", "set");
        
        // pres is an strophe helper to represent a presence status. after connecting, we tell the server we are online.
        connection.send($pres().tree());
        
        // An example of subscribing to another account
        //connection.send($pres({ to: "zhehao.mail.gmail.com@archive-dev.remap.ucla.edu", type: "subscribe" }));
    }
}

function joinRoom(roomJID, nickname) {
    // An example of joining a room
    connection.muc.join("room@conference.archive-dev.remap.ucla.edu", "pu", onMessage, onPresence, onRoster);
}

function sendMsg(toJID, content, type, fromNickname) {
    console.log("message sent");
    
    // An example of sending message
    // $msg is a helper function. .c() sets the element name, .t() the content.
    
    // type needs to be groupchat when targeting room@conference;
    var message = $msg({
      "to" : toJID,
      "type" : type,
      "from_nickname" : fromNickname,
    }).c("body").t(content);
    
    connection.send(message.tree()); 
}

function getRoster() {
    // An example of getting roster
    var iq = $iq({type: 'get'}).c('query', {xmlns: 'jabber:iq:roster'});
    connection.sendIQ(iq, function(res) {
      console.log(res);
      
      $(res).find('item').each(function(){
        var jid = $(this).attr('jid');     
        console.log(jid);
      })
    });
}

// Handler functions

function onPresence(presence) {
    console.log("onPresence");
    console.log(presence);
}

function onRoster(roster) {
    console.log("onRoster");
    console.log(roster);
}

function onMessage(msg) {
    console.log("onMessage called");
    
    var to = msg.getAttribute('to');
    var from = msg.getAttribute('from');
    var type = msg.getAttribute('type');
    var fromNickname = msg.getAttribute('from_nickname');
    
    if (fromNickname == null || fromNickname == undefined) {
        fromNickname = '';
    }
    
    var elems = msg.getElementsByTagName('body');
    
    if ((type == "chat" || type == "groupchat") && elems.length > 0) {
        var body = elems[0];
        
        $('#chat_display').val += fromNickname + '(' + from + ')' + ' : ' + Strophe.getText(body) + '\n';
    }

    // we must return true to keep the handler alive.  
    // returning false would remove it after it finishes.
    return true;
}

function chatConnect(jid, passwd) {
    connection.connect(jid, passwd, onConnect);
}

// Interface interaction functions
function sendClick() {
    var toJID = $('#input_jid').val;
    
}
