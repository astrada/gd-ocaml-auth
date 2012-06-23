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


import httplib2
import logging
import os
import sys

from google.appengine.ext import db
from google.appengine.api import users
from oauth2client import clientsecrets
from oauth2client.anyjson import simplejson
from oauth2client.client import Flow
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import OAuth2Credentials
from webapp2_extras.appengine.users import login_required

import webapp2


logger = logging.getLogger(__name__)

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')
SCOPES = 'https://docs.google.com/feeds/ https://docs.googleusercontent.com/ https://spreadsheets.google.com/feeds/'
REDIRECT_URI = 'https://gd-ocaml-auth.appspot.com/oauth2callback'

def render_error_page(response, error_msg):
  """Outputs an error page with a message."""
  response.headers['Content-Type'] = 'text/html'
  response.out.write(
      "<html xmlns='http://www.w3.org/1999/xhtml'><head><title>google-drive-ocamlfuse</title><link rel='stylesheet' href='/css/style.css' type='text/css' media='screen' /></head><body><div id='header'><h1>google-drive-ocamlfuse</h1></div><div id='content'><h1>Error</h1><p>{}</p></div></body></html>".format(error_msg))

def render_error_code(response, error_code):
  """ Outputs an error code to be read by the client application """
  response.headers['Content-Type'] = 'text/plain'
  response.out.write(error_code)

def get_auth_data(rid):
  """Gets an AuthData record from the data store."""
  key = AuthDataKey(rid)
  return AuthData.get(key.get_key())

def get_auth_error(rid):
  """Gets an AuthError record from the data store."""
  key = db.Key.from_path('AuthError', rid)
  return AuthError.get(key)

@db.transactional
def delete_auth_error(rid):
  """Transactionally deletes an AuthError record from the data store.

  If the record was not saved, do nothing."""
  auth_error = get_auth_error(rid)
  if auth_error:
    auth_error.delete()
  else:
    pass

@db.transactional
def put_auth_data(auth_data_key, rid, access, refresh):
  """Transactionally inserts a new instance of AuthData entity, checking if
  the key was already in use."""
  auth_data_key.check_presence()
  new_auth_data = AuthData(key_name=rid,
                           request_id=rid,
                           access_token=access,
                           refresh_token=refresh)
  new_auth_data.put()

def put_auth_error(rid, error_code):
  """Saves an AuthError record to the datastore."""
  new_auth_error = AuthError(key_name=rid,
                             request_id=rid,
                             error_code=error_code)
  new_auth_error.put()

def credentials_from_clientsecrets_and_token(filename, refresh_token):
  """Create a OAuth2Credentials from a clientsecrets file and AuthData
  record. """
  client_type, client_info = clientsecrets.loadfile(filename)
  if client_type in [clientsecrets.TYPE_WEB, clientsecrets.TYPE_INSTALLED]:
    return OAuth2Credentials(
        None,
        client_info['client_id'],
        client_info['client_secret'],
        refresh_token,
        None, # token_expiry
        'https://accounts.google.com/o/oauth2/token', # token_uri
        None) # user_agent
  else:
    raise UnknownClientSecretsFlowError(
        'This OAuth 2.0 flow is unsupported: "{}"'.format(client_type))

class ConflictError(Exception):
  """Exception raised when the request_id is already in use."""
  pass

class AuthData(db.Model):
  """Stores oauth2 tokens."""
  request_id = db.StringProperty(required=True)
  access_token = db.StringProperty(required=False)
  refresh_token = db.StringProperty(required=False)
  refresh_date = db.DateTimeProperty(auto_now_add=True)

  def to_json(self):
    """Serialize record to JSON."""
    d = {
        'request_id': self.request_id,
        'access_token': self.access_token,
        'refresh_token': self.refresh_token,
        'refresh_date': self.refresh_date.strftime(DATE_FORMAT)
    }
    return simplejson.dumps(d)

class AuthDataKey:
  """Helper class to handle AuthData keys."""

  def __init__(self, request_id):
    """Constructor for AuthDataKey."""
    self.request_id = request_id

  def get_key(self):
    """Builds an AuthData key from the request ID."""
    return db.Key.from_path('AuthData', self.request_id)

  def check_presence(self):
    """Checks if an entity is already present in the datastore. Raises
    ConflictError if it is. """
    key = self.get_key()
    obj = AuthData.get(key)
    if obj:
      raise ConflictError
    else:
      pass

class AuthError(db.Model):
  """Stores request ids that failed getting an auth token."""
  request_id = db.StringProperty(required=True)
  error_code = db.StringProperty(required=True)

class OAuth2Handler(webapp2.RequestHandler):
  """Handles oauth2 callback."""

  @login_required
  def get(self):
    rid = self.request.get('state')
    error = self.request.get('error')
    try:
      delete_auth_error(rid)
      if error:
        put_auth_error(rid, error)
        render_error_page(
            self.response,
            'The authorization request failed: {}'.format(error))
      else:
        try:
          auth_data_key = AuthDataKey(rid)
          auth_data_key.check_presence()
          flow = flow_from_clientsecrets(
              CLIENT_SECRETS,
              SCOPES,
              'Missing client_secrets.json')
          # Fake call to step 1 used to set redirect URI in Flow object
          flow.step1_get_authorize_url(redirect_uri=REDIRECT_URI)
          # Exchange code for an access token
          credentials = flow.step2_exchange(self.request.params)
          put_auth_data(
              auth_data_key, rid, credentials.access_token,
              credentials.refresh_token)
          self.redirect('/success.html')
        except ConflictError:
          logger.error('ConflictError: rid={}'.format(rid))
          put_auth_error(rid, "ConflictError")
          render_error_page(
              self.response,
              'Cannot store authorization tokens: requestid conflict, please try again')
    except:
      exc_info = sys.exc_info()
      logger.error('Exception: type={0} value={1} rid={2}'.format(
          exc_info[0],
          exc_info[1],
          rid))
      put_auth_error(rid, "Exception")
      render_error_page(
          self.response,
          'Cannot get authorization tokens: please try again')

class GetTokensHandler(webapp2.RequestHandler):
  """Returns stored oauth2 tokens by requestid."""

  def get(self):
    rid = self.request.get('requestid')
    if rid:
      auth_error = get_auth_error(rid)
      if auth_error:
        render_error_code(self.response, auth_error.error_code)
      else:
        auth_data = get_auth_data(rid)
        if auth_data:
          self.response.headers['Content-Type'] = 'application/json'
          self.response.out.write(auth_data.to_json())
          # If everything is fine, clean access tokens and leave the row just
          # for audit purposes
          auth_data.access_token = None
          auth_data.refresh_token = None
          auth_data.put()
        else:
          render_error_code(self.response, 'Not_found')
    else:
      render_error_code(self.response, 'Missing_request_id')

class RefreshTokenHandler(webapp2.RequestHandler):
  """Request a new oauth2 access token."""

  def get(self):
    token = self.request.get('token')
    if token:
      try:
        credentials = credentials_from_clientsecrets_and_token(
            CLIENT_SECRETS, token)
        h = httplib2.Http()
        credentials.refresh(h)
        auth_data = AuthData(request_id="dummy",
                             access_token=credentials.access_token,
                             refresh_token=token)
        self.response.headers['Content-Type'] = 'application/json'
        self.response.out.write(auth_data.to_json())
      except:
        render_error_code(self.response, 'Exception')
    else:
      render_error_code(self.response, 'Missing_refresh_token')


app = webapp2.WSGIApplication(
    [
      ('/oauth2callback', OAuth2Handler),
      ('/gettokens', GetTokensHandler),
      ('/refreshtoken', RefreshTokenHandler)
    ],
    debug=True)

