#
# Copyright 2014 David Novakovic
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from twisted.trial import unittest
from cyclone.web import Application, RequestHandler, asynchronous
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks

from autopush.tests.client import Client


class TestHandler(RequestHandler):
    def get(self):
        self.write("Something")

    def post(self):
        self.write("Something posted")

    def put(self):
        self.write("Something put")

    def head(self):
        self.write("")

    def delete(self):
        self.write("")


class DeferredTestHandler(RequestHandler):
    @asynchronous
    def get(self):
        self.write("Something...")
        reactor.callLater(0.1, self.do_something)

    def do_something(self):
        self.write("done!")
        self.finish()


class CookieTestHandler(RequestHandler):
    def get(self):
        self.set_secure_cookie("test_cookie", "test_value")
        self.finish()

    def post(self):
        value = self.get_secure_cookie("test_cookie")
        self.finish(value)


def mock_app_builder():
    return Application([
        (r'/testing/', TestHandler),
        (r'/deferred_testing/', DeferredTestHandler),
        (r'/cookie_testing/', CookieTestHandler),
    ], cookie_secret="insecure")


class TestClient(unittest.TestCase):
    def setUp(self):
        self.app = mock_app_builder()
        self.client = Client(self.app)

    def test_create_client(self):
        app = mock_app_builder()
        client = Client(app)
        self.assertTrue(client.app)

    @inlineCallbacks
    def test_get_request(self):
        response = yield self.client.get("/testing/")
        self.assertEqual(response.content, "Something")
        self.assertTrue(len(response.headers) > 3)

    @inlineCallbacks
    def test_get_request_with_params(self):
        response = yield self.client.get("/testing/", {"q": "query"})
        self.assertEqual(response.content, "Something")
        self.assertTrue(len(response.headers) > 3)

    @inlineCallbacks
    def test_post_request(self):
        response = yield self.client.post("/testing/")
        self.assertEqual(response.content, "Something posted")
        self.assertTrue(len(response.headers) > 3)

    @inlineCallbacks
    def test_put_request(self):
        response = yield self.client.put("/testing/")
        self.assertEqual(response.content, "Something put")
        self.assertTrue(len(response.headers) > 3)

    @inlineCallbacks
    def test_head_request(self):
        response = yield self.client.head("/testing/")
        self.assertEqual(response.content, "")
        self.assertTrue(len(response.headers) > 3)

    @inlineCallbacks
    def test_delete_request(self):
        response = yield self.client.delete("/testing/")
        self.assertEqual(response.content, "")
        self.assertTrue(len(response.headers) > 3)

    @inlineCallbacks
    def test_get_deferred_request(self):
        response = yield self.client.get("/deferred_testing/")
        self.assertEqual(response.content, "Something...done!")
        self.assertTrue(len(response.headers) > 3)

    @inlineCallbacks
    def test_cookies(self):
        response = yield self.client.get("/cookie_testing/")
        self.assertEqual(
            self.client.cookies.get_secure_cookie("test_cookie"),
            "test_value"
        )

        response = yield self.client.post("/cookie_testing/")
        self.assertEqual(response.content, "test_value")
