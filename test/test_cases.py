## Test cases for wbor.org functionality
# Author: Harrison Chapman


from google.appengine.dist import use_library
use_library('django', '1.3')

from google.appengine.ext import webapp
from google.appengine.ext import ndb
from google.appengine.ext import testbed
from webapp2 import Response, Request
from webapp2_extras import sessions

from models import Dj

import pprint

import unittest

from models.dj import *

from dj import app as dj_app
from main import app as main_app

#from handlers import BaseHandler
from configuration import webapp2conf

def get_session(response, app=main_app):
  pass
def get_response(request, app=main_app):
  response = request.get_response(app)
  cookies = response.headers['Set-Cookie']
  request = Request.blank('/', headers=[('Cookie', cookies)])
  request.app = app
  store = sessions.SessionStore(request)
  session = store.get_session()
  flashes = session.get_flashes()
  store.save_sessions(response)

  return response, session, flashes


class TestHandlers(unittest.TestCase):
  def set_cookie(self, response):
    self.cookies = response.headers['Set-Cookie']

  def setUp(self):
    self.testbed = testbed.Testbed()
    self.testbed.activate()
    self.testbed.setup_env
    self.testbed.init_datastore_v3_stub()
    self.testbed.init_memcache_stub()

    req = Request.blank('/setup')
    req.get_response(main_app)

    req = Request.blank('/dj/login', POST={'username': 'seth',
                                           'password': 'testme'})
    req.method = 'POST'
    res, self.session, flashes = get_response(req, app=dj_app)
    print flashes
    self.cookies = res.headers['Set-Cookie']

  def test_logged_in(self):
    self.assertEqual(self.session['dj']['username'], 'seth')

  def test_add_random_djs(self):
    names = file("./names")
    name_pairs = [(name.strip(),
                   (name[0] + name.split()[1]).lower().strip()) for
                  name in names]

    for name, uname in name_pairs:
      req = Request.blank('/dj/djs/', POST={
        'username': uname,
        'fullname': name,
        'email': uname,
        'password': "wbor",
        'confirm': "wbor",
        'submit': "Add DJ"})
      req.headers['Cookie'] = self.cookies
      req.method = 'POST'
      res, ses, flash = get_response(req, app=dj_app)
      self.assertEqual(u"success", flash[0][1])
      self.set_cookie(res)

    req = Request.blank('/dj/djs/')
    req.headers['Cookie'] = self.cookies
    req.get_response(dj_app)

    pprint.pprint([dj.raw for dj in Dj.get(num=1000)])

  def tearDown(self):
    self.testbed.deactivate()

if __name__ == "__main__":
  unittest.main()
