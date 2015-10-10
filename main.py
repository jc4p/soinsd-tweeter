from flask import Flask, request, redirect, render_template, abort
from flask import jsonify, session
from flask.ext.sqlalchemy import SQLAlchemy
import os
import tweepy
import hashlib

from secrets import *

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgres://soinsd@localhost/soinsd')
db = SQLAlchemy(app)
import models


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/login")
def login():
    auth = tweepy.OAuthHandler(TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET, "http://soinsd-tweeter.herokuapp.com/callback")
    redirect_url = auth.get_authorization_url(signin_with_twitter=True)
    session['request_token'] = auth.request_token
    return redirect(redirect_url)

@app.route("/callback")
def callback():
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    verifier = request.args.get('oauth_verifier', '')    
    auth.request_token = session.pop('request_token', None)
    auth.get_access_token(verifier)
    
    api = tweepy.API(auth)
    user = api.me()

    hash_object = hashlib.sha256(FLASK_SECRET_KEY + auth.access_token)
    hash_hex = hash_object.hexdigest()
    session['auth_hash'] = hash_hex
    session['username'] = user.screen_name

    user = models.User(user.screen_name, auth.access_token, auth.access_token_secret, hash_hex)
    db.session.add(user)
    db.session.commit()
    return redirect("/hash")

@app.route("/hash")
def hash():
    hash_hex = session.get('hash_hex', None)
    username = session.get('username', None)
    if not (hash_hex and username):
        abort(404)
    return render_template('hash.html', username=username, hash_hex=hash_hex)


if __name__ == '__main__':
    app.run()
