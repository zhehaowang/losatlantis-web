// TODO: Figuring out what the number after the jid means.
// TODO: chatDisconnect onPageUnload's synchronous call on Strophe.Connection.disconnect seems to cause freeze when operating too fast

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
                
        // Jabber actions differ by different types of identities
        if (userType == 0) {
          // for Watchers, they join a chatroom: 
          // Note: this actually introduces the requirement of a globally unique user name, which is not ideal
          // Note: we already have onMessage callback for all messages directed at this JID/chatroom
          connection.muc.join(defaultChatroom, nickname, null, onPresence, onRoster);
        } else if (userType == 1) {
          // for Tourists, they receive messages directed at them:
          
        } else if (userType == 2) {
          // for Crew, they can send anything to anyone
          // Currently for crew to be able to push MUC message, they'll join the chatroom as well.
          
        }
    }
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
    
    //$('#chat_display').append('System: chatroom roster \"' + presence.getAttribute('from') + '\"\n');
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
    
    if (elems.length > 0) {
        var body = elems[0];
        if ((type == "chat" || type == "groupchat")) {
            $('#chat_display').append(fromNickname + '(' + from + ')' + ' : ' + Strophe.getText(body) + '\n');
        } else if (type == "error") {
            $('#chat_display').append('Error sending: \"' + Strophe.getText(body) + '\"\n');
        }
    }
    
    // we must return true to keep the handler alive.  
    // returning false would remove it after it finishes.
    return true;
}

function chatConnect(jid, passwd) {
    connection.connect(jid, passwd, onConnect);
}

function chatDisconnect() {
    // Switch to using synchronous requests since this is typically called onUnload.
    connection.options.sync = true; 
    connection.flush();
    connection.disconnect();
}

// Interface interaction functions

function sendClick() {
    var toJID = $('#input_jid').val();
    var type = $('#input_type').val();
    var content = $('#input_msg').val();
    var from_nickname = nickname;
    
    console.log(toJID);
    
    sendMsg(toJID, content, type, from_nickname);
}

function joinClick() {
    var roomJID = $('#input_room_jid').val();
    connection.muc.join(roomJID, nickname, null, onPresence, onRoster);
}
