#!/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, g, session, flash, \
     redirect, url_for, abort
from flask.ext.openid import OpenID

from openid.extensions import pape

from cassandra import ConsistencyLevel
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement

from email.utils import parseaddr

# setup flask
app = Flask(__name__)
app.config.update(
    SECRET_KEY = 'development key',
    DEBUG = True,
    
    # Database configuration
    DATABASE_URI = 'localhost',
    KEYSPACE_NAME = 'losatlantis'
)

# Right now we are not using a Model mapping tool, such as sqlalchemy or cqlengine
class Users(object):
    
    _name = ''
    _email = ''
    _password = ''
    _openid = []
    _type = -1
    
    def update(self, query):
        username = ''
        if hasattr(query, 'user_name') and (not query.user_name is None):
            username = query.user_name
        openids = []
        if hasattr(query, 'openid') and (not query.openid is None):
            openids = query.openid
        type = -1
        if hasattr(query, 'type') and (not query.type is None):
            type = int(query.type)
        passwd = ''
        if hasattr(query, 'password') and (not query.password is None):
            passwd = query.password
        
        self._name = username
        self._email = query.email
        self.password = passwd
        self._openid = openids
        self._type = type

        return self
        
    def __init__(self, name = '', email = '', openid = [], type = -1, password = ''):
        self._name = name
        self._email = email
        self.password = password
        self._openid = openid
        self._type = type

# setup flask-openid
oid = OpenID(app, safe_roots=[], extension_responses=[pape.Response])

cluster = Cluster(
    contact_points = [app.config['DATABASE_URI']],
)

db_session = cluster.connect(app.config['KEYSPACE_NAME'])

@app.before_request
def before_request():
    g.user = None
    if 'email' in session:
        results = db_session.execute('select * from users where email = \'%s\'' % session['email'])
        if results is not None and len(results) > 0:
            g.user = Users()
            g.user.update(results[0])
        
@app.after_request
def after_request(response):
    # Do we call db_session's disconnect
    return response


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    if g.user is not None:
        return redirect(oid.get_next_url())
    return render_template('login.html', next=oid.get_next_url(),
                           error=oid.fetch_error())

# Does the login via OpenID.  Has to call into "oid.try_login"
# to start the OpenID machinery.
# if we are already logged in, go back to were we came from
    
# For a list of urls of openid providers: 
# http://stackoverflow.com/questions/1116743/where-can-i-find-a-list-of-openid-provider-urls

@app.route('/login_oid', methods=['GET', 'POST'])
@oid.loginhandler
def login_oid():
    if g.user is not None:
        return redirect(oid.get_next_url())
    if request.method == 'POST':
        openid = request.form.get('openid_identifier')
        use_oidc = request.form.get('use_oidc_identifier')
        
        if __debug__:
            print('Received openid: ' + openid)
            print('Received use_oidc: ' + use_oidc)
            
        if openid:
            pape_req = pape.Request([])
            if use_oidc != None and use_oidc != "1":
                return oid.try_login(openid, ask_for=['email', 'nickname'],
                                             ask_for_optional=['fullname'],
                                             extensions=[pape_req])
            else:
                print('OpenID Connect is not supported yet')
                
    return render_template('login.html', next=oid.get_next_url(),
                           error=oid.fetch_error())

@app.route('/login_own', methods=['POST'])
def login_own():
    email = request.form.get('signin_email')
    passwd = request.form.get('signin_password')
    
    # Note: This should probably be handled in frontend, at some point
    if email is None or passwd is None or email == '' or passwd == '':
        flash(u'Empty email or password')
        return redirect(url_for('login'))
    
    results = db_session.execute('select email, password, type from users where email = \'%s\'' % email)
    if results is not None and len(results) > 0:
        # Note: for debug passwd is stored as plain text, will change later;
        if (results[0].password is not None and results[0].password != '' and passwd == results[0].password):
            flash(u'Successfully signed in')
            
            g.user = Users()
            g.user.update(results[0])
            session['email'] = email
            
            # Figuring out if some sort of 'next' should be used for ordinary sign-ins
            return redirect(url_for('index'))
        else:
            # A user cannot sign in with ordinary methods, if he only has OpenID signin records
            flash(u'User passwd wrong or not set')
            return redirect(url_for('login'))
    else: 
        flash(u'User record does not exist')
        return redirect(url_for('login'))
        
@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('registration_email')
    passwd = request.form.get('registration_password')
    passwd_confirm = request.form.get('registration_password_confirm')
    user_name = request.form.get('registration_user_name')
    type = int(request.form.get('registration_type'))
    
    # Note: This should probably be handled in frontend, at some point
    if email is None or passwd is None or email == '' or passwd == '':
        flash(u'Empty email or password')
        return redirect(url_for('login'))
        
    if '@' not in parseaddr(email)[1]:
        flash(u'Illegal email address')
        return redirect(url_for('login'))
        
    if (passwd != passwd_confirm):
        flash(u'Password mismatch')
        return redirect(url_for('login'))
        
    results = db_session.execute('select * from users where email = \'%s\'' % email)
    if (not results is None) and len(results) > 0:
        # This email address only had OpenID login records, we update his records and set his password
        # Right now for debug, this process does not require email authentication, same for other registration related things.
        if (not hasattr(results[0], 'password')) or results[0].password is None or results[0].password == '':
            flash(u'Profile successfully created, you can now login')
            if (user_name == ''):
                db_session.execute('update users set password = \'%s\', type = %d where email = \'%s\'' % (passwd, type, email))
            else:
                db_session.execute('update users set password = \'%s\', user_name = \'%s\', type = %d where email = \'%s\'' % (passwd, user_name, type, email))
            return redirect(url_for('login'))
        # This account already exists, we can't register it again
        else:
            flash(u'Profile already exists')
            return redirect(url_for('login'))
    else:
        # This email address does not have related records, we create a new profile
        flash(u'Profile successfully created, you can now login')
        db_session.execute('insert into users (user_name, email, password, type) values (\'%s\', \'%s\', \'%s\', %d)' % (user_name, email, passwd, type))
        return redirect(url_for('login'))
    return redirect(url_for('login'))

# This is called when login with OpenID succeeded and it's not
# necessary to figure out if this is the users's first login or not.
# This function has to redirect otherwise the user will be presented
# with a terrible URL which we certainly don't want.
# This is only used by login with OpenID
@oid.after_login
def create_or_login(resp):
    session['openid'] = resp.identity_url
    # Note: is there an OpenID account that is not identifiable by email?
    session['email'] = resp.email
    
    if 'pape' in resp.extensions:
        pape_resp = resp.extensions['pape']
        session['auth_time'] = pape_resp.auth_time
        
    results = db_session.execute('select * from users where email = \'%s\'' % resp.email)
    if results is not None and len(results) > 0:
        flash(u'Successfully signed in')
        g.user = Users()
        g.user.update(results[0])
        # It's not necessary that we store openID now, but we do so anyway.
        if (results[0].openid is not None and session['openid'] not in results[0].openid):
            db_session.execute('update users set openid = openid + [\'%s\'] where email = \'%s\'' % (session['openid'], resp.email))
        return redirect(oid.get_next_url())
    return redirect(url_for('create_profile', next=oid.get_next_url(),
                            name=resp.fullname or resp.nickname,
                            email=resp.email))

# If this is the user's first login, the create_or_login function
# will redirect here so that the user can set up his profile.
# Create profile is only usde by OpenID login now.
@app.route('/create-profile', methods=['GET', 'POST'])
def create_profile():
    if (not g.user is None) or 'openid' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        type = int(request.form['type'])
        
        if not name:
            flash(u'Error: you have to provide a name')
        elif '@' not in email:
            flash(u'Error: you have to enter a valid email address')
        else:
            flash(u'Profile successfully created')
            db_session.execute('insert into users (user_name, email, type) values (\'%s\', \'%s\', %d)' % (name, email, type))
            # It's not necessary that we store openID now, but we do so anyway.
            db_session.execute('update users set openid = openid + [\'%s\'] where email = \'%s\'' % (session['openid'], email))
            return redirect(oid.get_next_url())
    return render_template('create_profile.html', next_url=oid.get_next_url())

# Update the profile; we do not allow people to update their email address?
@app.route('/profile', methods=['GET', 'POST'])
def edit_profile():
    if g.user is None:
        abort(401)
    form = dict(name=g.user._name, email=g.user._email, type=g.user._type)
    if request.method == 'POST':
        if 'delete' in request.form:
            # Note: Two entries with the same email address: maybe email should be primary key?
            db_session.execute('delete from users where email=\'%s\'' % g.user._email)
            
            session['openid'] = None
            session['email'] = None
            
            flash(u'Profile deleted')
            return redirect(url_for('index'))
        form['name'] = request.form['name']
        form['email'] = request.form['email']
        form['type'] = int(request.form['type'])
        if not form['name']:
            flash(u'Please provide a name')
        else:
            flash(u'Profile successfully updated')
            # Note: Two entries with the same email address: maybe email should be primary key?
            db_session.execute('update users set user_name = \'%s\', type = %d where email = \'%s\'' % (form['name'], form['type'], g.user._email))
            g.user._name = form['name']
            g.user._email = form['email']
            g.user._type = form['type']
            return redirect(url_for('edit_profile'))
    return render_template('edit_profile.html', form=form)

@app.route('/logout')
def logout():
    print("*** logout called ***")
    print(oid.get_next_url())
    session.pop('openid', None)
    session.pop('email', None)
    flash(u'You have been signed out')
    # Note: logout will want a constant redirect to something like index.html, which may not be ideal in certain cases?
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
