# Copyright (C) 2012-2015 Alessandro Strada
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
import datetime
import httplib2
import logging
import os

from google.appengine.ext import ndb
from oauth2client import clientsecrets
from oauth2client.anyjson import simplejson
import oauth2client.client as oa2client
import webapp2


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')
SCOPES = 'https://www.googleapis.com/auth/drive'
REDIRECT_URI = 'https://gd-ocaml-auth.appspot.com/oauth2callback'


def render_error_page(response, error_msg):
    """Outputs an error page with a message."""
    response.headers['Content-Type'] = 'text/html'
    response.out.write(
        "<html xmlns='http://www.w3.org/1999/xhtml'><head><title>gdfuse</title>" +
        "<link rel='stylesheet' href='/css/style.css' type='text/css' media='screen' /></head><body>" +
        "<div id='header'><h1>gdfuse</h1></div><div id='content'>" +
        "<h1>Error</h1><p>{}</p></div></body></html>".format(error_msg))


def render_error_code(response, error_code):
    """ Outputs an error code to be read by the client application """
    response.headers['Content-Type'] = 'text/plain'
    response.out.write(error_code)


class AuthData(ndb.Model):
    """Stores oauth2 tokens."""
    request_id = ndb.StringProperty(required=True, indexed=False)
    access_token = ndb.StringProperty(indexed=False)
    refresh_token = ndb.StringProperty(indexed=False)
    refresh_date = ndb.DateTimeProperty(auto_now_add=True, indexed=False)

    def to_json(self):
        """Serialize record to JSON."""
        d = {
            'request_id': self.request_id,
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'refresh_date': self.refresh_date.strftime(DATE_FORMAT)
        }
        return simplejson.dumps(d)


class AuthError(ndb.Model):
    """Stores request ids that failed getting an auth token."""
    request_id = ndb.StringProperty(required=True, indexed=False)
    error_code = ndb.StringProperty(required=True, indexed=False)


def get_auth_data(rid):
    """Gets an AuthData record from the data store."""
    return AuthData.get_by_id(rid)


def get_auth_error(rid):
    """Gets an AuthError record from the data store."""
    return AuthError.get_by_id(rid)


def delete_auth_error(rid):
    """Deletes an AuthError record from the data store."""
    ndb.Key(AuthError, rid).delete()


def put_auth_data(rid, access, refresh):
    """Inserts a new instance of AuthData entity."""
    new_auth_data = AuthData(id=rid,
                             request_id=rid,
                             access_token=access,
                             refresh_token=refresh)
    new_auth_data.put()


def put_auth_error(rid, error_code):
    """Saves an AuthError record to the data-store."""
    new_auth_error = AuthError(id=rid,
                               request_id=rid,
                               error_code=error_code)
    new_auth_error.put()


def credentials_from_client_secrets_and_token(filename, refresh_token):
    """Create a OAuth2Credentials from a client-secrets file and AuthData
    record. """
    client_type, client_info = clientsecrets.loadfile(filename)
    if client_type in [clientsecrets.TYPE_WEB, clientsecrets.TYPE_INSTALLED]:
        return oa2client.OAuth2Credentials(
            None,
            client_info['client_id'],
            client_info['client_secret'],
            refresh_token,
            None,  # token_expiry
            'https://accounts.google.com/o/oauth2/token',  # token_uri
            None)  # user_agent
    else:
        raise oa2client.UnknownClientSecretsFlowError('This OAuth 2.0 flow is unsupported: "{}"'.format(client_type))


class OAuth2Handler(webapp2.RequestHandler):
    """Handles oauth2 callback."""

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
                flow = oa2client.flow_from_clientsecrets(
                    CLIENT_SECRETS,
                    SCOPES,
                    redirect_uri=REDIRECT_URI,
                    message='Missing client_secrets.json')
                # Exchange code for an access token
                credentials = flow.step2_exchange(self.request.params)
                put_auth_data(rid, credentials.access_token, credentials.refresh_token)
                self.redirect('/success.html')
        except Exception, e:
            logging.exception('Exception: type={} message={} rid={}'.format(
                e.__class__.__name__,
                e.message,
                rid))
            put_auth_error(rid, "Exception")
            render_error_page(
                self.response,
                'Cannot get authorization tokens: please try again')


class GetTokensHandler(webapp2.RequestHandler):
    """Returns stored oauth2 tokens by request-id."""

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
                credentials = credentials_from_client_secrets_and_token(
                    CLIENT_SECRETS, token)
                h = httplib2.Http()
                credentials.refresh(h)
                auth_data = AuthData(request_id="dummy",
                                     access_token=credentials.access_token,
                                     refresh_token=token,
                                     refresh_date=datetime.datetime.utcnow())
                self.response.headers['Content-Type'] = 'application/json'
                self.response.out.write(auth_data.to_json())
            except Exception, e:
                logging.exception('Exception: type={} message={}'.format(
                    e.__class__.__name__,
                    e.message))
                render_error_code(self.response, 'Exception')
        else:
            render_error_code(self.response, 'Missing_refresh_token')


app = webapp2.WSGIApplication(
    [('/oauth2callback', OAuth2Handler),
     ('/gettokens', GetTokensHandler),
     ('/refreshtoken', RefreshTokenHandler)])
