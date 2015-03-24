#!/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, g, session, flash, \
     redirect, url_for, abort
from flask.ext.openid import OpenID

from openid.extensions import pape

from cassandra import ConsistencyLevel
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement

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
    _openid = ''
    
    def __init__(self, name, email, openid, password=''):
        self._name = name
        self._email = email
        self.password = password
        self._openid = openid

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
        result = db_session.execute('select * from users where email = \'%s\'' % session['email'])
        # Safe to make the assumption that query always has results?
        if result is not None and len(result) > 0:
            g.user = Users(result[0].user_name, result[0].email, result[0].openid)
        
@app.after_request
def after_request(response):
    # Do we call db_session's disconnect
    return response


@app.route('/')
def index():
    return render_template('index.html')

# Does the login via OpenID.  Has to call into "oid.try_login"
# to start the OpenID machinery.
# if we are already logged in, go back to were we came from
    
# For a list of urls of openid providers: 
# http://stackoverflow.com/questions/1116743/where-can-i-find-a-list-of-openid-provider-urls

@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
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
                print('OpenID connect is not supported yet')
                
    return render_template('login.html', next=oid.get_next_url(),
                           error=oid.fetch_error())

# This is called when login with OpenID succeeded and it's not
# necessary to figure out if this is the users's first login or not.
# This function has to redirect otherwise the user will be presented
# with a terrible URL which we certainly don't want.
@oid.after_login
def create_or_login(resp):
    session['openid'] = resp.identity_url
    # Note: is there an OpenID account that is not identifiable by email?
    session['email'] = resp.email
    
    if 'pape' in resp.extensions:
        pape_resp = resp.extensions['pape']
        session['auth_time'] = pape_resp.auth_time
        
    result = db_session.execute('select * from users where email = \'%s\'' % resp.email)
    if result is not None and len(result) > 0:
        flash(u'Successfully signed in')
        g.user = Users(result[0].user_name, result[0].email, result[0].openid)
        return redirect(oid.get_next_url())
    return redirect(url_for('create_profile', next=oid.get_next_url(),
                            name=resp.fullname or resp.nickname,
                            email=resp.email))

# If this is the user's first login, the create_or_login function
# will redirect here so that the user can set up his profile.
@app.route('/create-profile', methods=['GET', 'POST'])
def create_profile():
    if g.user is not None or 'openid' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        if not name:
            flash(u'Error: you have to provide a name')
        elif '@' not in email:
            flash(u'Error: you have to enter a valid email address')
        else:
            flash(u'Profile successfully created')
            db_session.execute('insert into users (user_name, email) values (\'%s\', \'%s\')' % (name, email))
            # It's not necessary that we store openID now, but we do so anyway.
            db_session.execute('update users set openid = openid + [\'%s\'] where email = \'%s\'' % (session['openid'], email))
            return redirect(oid.get_next_url())
    return render_template('create_profile.html', next_url=oid.get_next_url())

# Update the profile; we do not allow people to update their email address?
@app.route('/profile', methods=['GET', 'POST'])
def edit_profile():
    if g.user is None:
        abort(401)
    form = dict(name=g.user._name, email=g.user._email)
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
        if not form['name']:
            flash(u'Error: you have to provide a name')
        else:
            flash(u'Profile successfully created')
            # Note: Two entries with the same email address: maybe email should be primary key?
            db_session.execute('update users set user_name=\'%s\' where email=\'%s\'' % (form['name'], g.user._email))
            g.user._name = form['name']
            g.user._email = form['email']
            return redirect(url_for('edit_profile'))
    return render_template('edit_profile.html', form=form)

@app.route('/logout')
def logout():
    print("*** logout called ***")
    print(oid.get_next_url())
    session.pop('openid', None)
    session.pop('email', None)
    flash(u'You have been signed out')
    # Note: logout will want a constant redirect to something like index.html, which is not implemented
    return redirect(oid.get_next_url())


if __name__ == '__main__':
    app.run()
