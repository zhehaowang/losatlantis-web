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
        
        connection.addHandler(onMessage, null, 'message', null, null,  null); 
        connection.send($pres().tree());
    }
}

function sendMsg(to_jid, content)
{
    console.log("message sent");
    
    // $msg is a helper function. .c() sets the element name, .t() the content.
	var message = $msg({
	  "to" : to_jid,
	  "type" : "chat",
	  "from_nickname" : "zhehao",
	}).c("body").t(content);
	
	// And we send the created Message
	connection.send(message.tree()); 
}

function onMessage(msg) {
    console.log("onMessage called");
    
    var to = msg.getAttribute('to');
    var from = msg.getAttribute('from');
    var type = msg.getAttribute('type');
    var elems = msg.getElementsByTagName('body');
    
    if (type == "chat" && elems.length > 0) {
        var body = elems[0];

        console.log('I got a message from ' + from + ': ' + 
            Strophe.getText(body));
        
        // Following code used by EchoBot:
        /*
        var reply = $msg({to: from, from: to, type: 'chat'})
            .cnode(Strophe.copyElement(body));
        connection.send(reply.tree());
        
        console.log('ECHOBOT: I sent ' + from + ': ' + Strophe.getText(body));
        */
    }

    // we must return true to keep the handler alive.  
    // returning false would remove it after it finishes.
    return true;
}

function chatConnect(jid, passwd) {
    connection.connect(jid, passwd, onConnect);
}
