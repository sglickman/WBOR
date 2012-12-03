## Test cases for wbor.org functionality
# Author: Harrison Chapman


from google.appengine.dist import use_library
use_library('django', '1.3')

from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.ext import testbed
from webapp2 import Response, Request

import unittest

from models.dj import *

from dj import app as dj_app
from main import app as main_app

#from handlers import BaseHandler
from configuration import webapp2conf


class TestHandlers(unittest.TestCase):
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
    res = req.get_response(dj_app)
    self.cookies = res.headers['Set-Cookie']
    print self.cookies

  def test_add_random_djs(self):
    names = file("./names")


    for name in names:
      req = Request.blank('/dj/djs/', POST={
        'username': 'guy',
        'fullname': 'Guy Fieri',
        'email': "guy",
        'password': "wbor",
        'confirm': "wbor",
        'submit': "Add DJ"})
      req.headers['Cookie'] = self.cookies
      req.method = 'POST'
      print req.get_response(dj_app)

    req = Request.blank('/dj/djs/')
    req.headers['Cookie'] = self.cookies
    print req
    print req.get_response(dj_app)

  def tearDown(self):
    self.testbed.deactivate()

if __name__ == "__main__":
  unittest.main()
