# Copyright (C) 2012 Alessandro Strada
# based on oauth2client/appengine.py Copyright (C) 2010 Google Inc.
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

import pickle

from google.appengine.api import memcache
from google.appengine.api import users
from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import Credentials
from oauth2client.client import Flow
from oauth2client.client import Storage
from oauth2client.appengine import CredentialsModel
from oauth2client.appengine import StorageByKeyName
from webapp2_extras.appengine.users import login_required

import webapp2

OAUTH2CLIENT_NAMESPACE = 'oauth2client#ns'


class OAuth2Handler(webapp2.RequestHandler):
  @login_required
  def get(self):
    error = self.request.get('error')
    if error:
      errormsg = self.request.get('error_description', error)
      self.response.out.write(
          'The authorization request failed: %s' % errormsg)
    else:
      user = users.get_current_user()
      flow = pickle.loads(memcache.get(user.user_id(),
                                       namespace=OAUTH2CLIENT_NAMESPACE))
      if flow:
        credentials = flow.step2_exchange(self.request.params)
        StorageByKeyName(
            CredentialsModel, user.user_id(), 'credentials').put(credentials)
        self.response.out.write(
            'The authorization request succeded: state=%s' %
            str(self.request.get('state')))
      else:
        pass


app = webapp2.WSGIApplication(
    [
      ('/oauth2callback', OAuth2Handler)
    ],
    debug=True)

