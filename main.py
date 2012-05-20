# Copyright (C) 2012 Alessandro Strada
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# OAuth2
import os

from google.appengine.api import users
from oauth2client.client import OAuth2Credentials
from oauth2client.client import Flow
from oauth2client.client import flow_from_clientsecrets
from webapp2_extras.appengine.users import login_required

# Datastore
from google.appengine.ext import db

# JSON
import simplejson

import webapp2


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')
SCOPES = 'https://docs.google.com/feeds/ https://docs.googleusercontent.com/ https://spreadsheets.google.com/feeds/'

# Outputs an error page with a message
def render_error_page(response, error_msg):
  response.headers['Content-Type'] = 'text/html'
  response.out.write(
      "<html xmlns='http://www.w3.org/1999/xhtml'><head><title>google-drive-ocamlfuse</title><link rel='stylesheet' href='/css/style.css' type='text/css' media='screen' /></head><body><div id='header'><h1>google-drive-ocamlfuse</h1></div><div id='content'><h1>Error</h1><p>{}</p></div></body></html>".format(error_msg))

# Check if an entity is already present in the datastore. Raises ConflictError
# if it is.
def check_presence(key):
  obj = db.get(key)
  if obj:
    raise ConflictError
  else:
    pass

# Transactionally insert a new instance of AuthData entity, checking if the
# key was already in use.
@db.transactional
def put_auth_data(key, rid, uid, access, refresh):
  check_presence(key)
  new_auth_data = AuthData(key_name=rid,
                           request_id=rid,
                           user_id=uid,
                           access_token=access,
                           refresh_token=refresh)
  new_auth_data.put()

class ConflictError(Exception):
  """ Exception raised when the request_id is already in use """
  pass

class AuthData(db.Model):
  """ Stores oauth2 tokens """
  request_id = db.StringProperty(required=True)
  user_id = db.StringProperty(required=True)
  access_token = db.StringProperty(required=True)
  refresh_token = db.StringProperty(required=True)
  date = db.DateTimeProperty(auto_now_add=True)

  def to_json(self):
    d = {
        'request_id': self.request_id,
        'user_id': self.user_id,
        'access_token': self.access_token,
        'refresh_token': self.refresh_token,
        'date': self.date.strftime(DATE_FORMAT)
    }
    return simplejson.dumps(d)

class OAuth2Handler(webapp2.RequestHandler):
  """ Handles oauth2 callback """
  @login_required
  def get(self):
    error = self.request.get('error')
    if error:
      error_msg = self.request.get('error_description', error)
      self.response.headers['Content-Type'] = 'text/plain'
      self.response.out.write(
          'The authorization request failed: %s' % error_msg)
    else:
      rid = self.request.get('state')
      key = db.Key.from_path('AuthData', rid)
      try:
        check_presence(key)
        user = users.get_current_user()
        flow = flow_from_clientsecrets(
            CLIENT_SECRETS,
            SCOPES,
            'Missing client_secrets.json')
        if flow:
          # Fake call to step 1 used to set redirect URI in Flow object
          flow.step1_get_authorize_url(
              redirect_uri='http://localhost:8080/oauth2callback')
          # Real call to step 2
          credentials = flow.step2_exchange(self.request.params)
          put_auth_data(
              key, rid, user.user_id(), credentials.access_token,
              credentials.refresh_token)
          self.redirect('/success.html')
        else:
          self.response.headers['Content-Type'] = 'text/plain'
          self.response.out.write(
              'The authorization request failed: Cannot continue oauth2 flow')
      except ConflictError:
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write(
            'The authorization request failed: Request ID conflict')

class GetTokensHandler(webapp2.RequestHandler):
  """ Returns stored oauth2 tokens by requestid """
  def get(self):
    rid = self.request.get('requestid')
    if rid:
      key = db.Key.from_path('AuthData', rid)
      auth_data = AuthData.get(key)
      if auth_data:
        self.response.headers['Content-Type'] = 'application/json'
        self.response.out.write(auth_data.to_json())
      else:
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Not_found')
    else:
      render_error_page(
          self.response,
          'Cannot retrieve authorization tokens: requestid not provided')


app = webapp2.WSGIApplication(
    [
      ('/oauth2callback', OAuth2Handler),
      ('/gettokens', GetTokensHandler)
    ],
    debug=True)

