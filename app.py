# Python standard libraries
import json
import os
import sqlite3
import oauthlib
import configparser

# Third-party libraries
from flask import Flask, redirect, request, url_for,render_template
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

# Internal imports
from db import init_db_command
from user import User
from flask_assets import Bundle, Environment





# Configuration
config = configparser.ConfigParser()
config.sections()

config.read('config.ini')

WS1_CLIENT_ID = config['DEFAULT']['WS1_CLIENT_ID']
WS1_CLIENT_SECRET = config['DEFAULT']['WS1_CLIENT_SECRET']
WS1_DISCOVERY_URL = config['DEFAULT']['WS1_DISCOVERY_URL']
REDIRECT_HTTPS = config['DEFAULT']['REDIRECT_HTTPS']

if REDIRECT_HTTPS.lower() == 'true':
    REDIRECT_HTTPS = True
else:
    REDIRECT_HTTPS = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

env = Environment(app)
js = Bundle('https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js',
            'https://code.jquery.com/ui/1.12.1/jquery-ui.js' ,'js/test.js')
env.register('js_all', js)


# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)

# Naive database setup
try:
    init_db_command()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass

# OAuth 2 client setup
client = WebApplicationClient(WS1_CLIENT_ID)


def get_ws1_provider_cfg():
    return requests.get(WS1_DISCOVERY_URL).json()


# Flask-Login helper to retrieve a user from our db
@login_manager.unauthorized_handler
def unauthorized():
    # do stuff
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/")
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            '<a class="button" href="/speedtest">SpeedTest</a>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">WS1 Login</a><br>'


@app.route("/login")
def login():
    # Find out what URL to hit for WS1 login
    ws1_provider_cfg = get_ws1_provider_cfg()
    authorization_endpoint = ws1_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for WS1 login and provide
    # scopes that let you retrieve user's profile from WS1
    redirect_uri = request.base_url + "/callback"
    if REDIRECT_HTTPS:
        redirect_uri = redirect_uri.replace('http://', 'https://')
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=redirect_uri,
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    # Get authorization code WS1 sent back to you
    code = request.args.get("code")
    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    ws1_provider_cfg = get_ws1_provider_cfg()
    token_endpoint = ws1_provider_cfg["token_endpoint"]
    # Prepare and send a request to get tokens! Yay tokens!
    try:
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=request.base_url,
            code=code
        )
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(WS1_CLIENT_ID, WS1_CLIENT_SECRET),
        )
    except oauthlib.oauth2.rfc6749.errors.InvalidClientIdError as e:
        #oauthlib.oauth2.rfc6749.errors.InvalidClientIdError: (invalid_request) User+not+entitled+to+the+OIDC+resource.
        return str(e)

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))
    # Now that you have tokens (yay) let's find and hit the URL
    # from WS1 that gives you the user's profile information,
    # including their WS1 profile image and email
    userinfo_endpoint = ws1_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    print(userinfo_response.json())
    # You want to make sure their email is verified.
    # The user authenticated with WS1, authorized your
    # app, and now you've verified their email through WS1!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        # picture = userinfo_response.json()["picture"]
        picture = ''
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by WS1.", 400

    # Create a user in your db with the information provided
    # by WS1
    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )

    # Doesn't exist? Add it to the database.
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    # Begin user session by logging the user in
    login_user(user)

    # Send user back to homepage
    return redirect(url_for("index"))


@app.route('/speedtest')
@login_required
def speedtest():
    return render_template('speedtest.html')

@app.route('/ip', methods=[ 'POST', 'GET'])
@login_required

def ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    else:
        ip = request.remote_addr
    return str(ip)


@app.route('/empty', methods=[ 'POST', 'GET'])
@login_required
def empty():
    return ''


@app.route('/download')
@login_required
def download():
    return "download file"

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))




if __name__ == "__main__":
    #ssl
    app.run(ssl_context="adhoc")
    #non-ssl
    #app.run()