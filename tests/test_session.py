"""Unit tests for xssmap.session (cookie jar, login flow, CSRF tokens).

These tests never open a socket: the login flow is exercised against a fake
HTTP client that records the request it was given.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssmap.session import (
    Cookie,
    CookieJar,
    Session,
    csrf_tokens,
    is_login_form,
    parse_set_cookie,
)


class SetCookieParsing(unittest.TestCase):
    def test_plain_cookie_is_host_only(self):
        cookie = parse_set_cookie("http://a.example/login", "sid=abc123")
        self.assertEqual((cookie.name, cookie.value), ("sid", "abc123"))
        self.assertEqual(cookie.domain, "a.example")
        self.assertEqual(cookie.path, "/")
        self.assertTrue(cookie.host_only)
        self.assertFalse(cookie.secure)
        self.assertEqual(cookie.expires, 0.0)

    def test_attributes(self):
        cookie = parse_set_cookie(
            "https://a.example/deep/page",
            "sid=x; Domain=.example.com; Path=/deep; Secure; Max-Age=600")
        self.assertEqual(cookie.domain, "example.com")
        self.assertFalse(cookie.host_only)
        self.assertEqual(cookie.path, "/deep")
        self.assertTrue(cookie.secure)
        self.assertGreater(cookie.expires, 0)

    def test_max_age_zero_deletes(self):
        jar = CookieJar()
        jar.update_from_response("http://a.example/", [("Set-Cookie", "sid=abc")])
        self.assertEqual(jar.names(), ["sid"])
        jar.update_from_response("http://a.example/", [("Set-Cookie", "sid=; Max-Age=0")])
        self.assertEqual(jar.names(), [])
        self.assertEqual(jar.header_for("http://a.example/"), "")

    def test_garbage_is_ignored(self):
        self.assertIsNone(parse_set_cookie("http://a.example/", "no-equals-sign"))
        self.assertIsNone(parse_set_cookie("http://a.example/", "=value"))


class Matching(unittest.TestCase):
    def test_host_only_does_not_leak_to_subdomains(self):
        jar = CookieJar()
        jar.update_from_response("http://a.example/", [("Set-Cookie", "sid=abc")])
        self.assertEqual(jar.header_for("http://a.example/x"), "sid=abc")
        self.assertEqual(jar.header_for("http://b.a.example/"), "")

    def test_domain_cookie_reaches_subdomains(self):
        jar = CookieJar()
        jar.update_from_response("http://a.example/",
                                 [("Set-Cookie", "theme=dark; Domain=example.com")])
        self.assertEqual(jar.header_for("http://shop.example.com/"), "theme=dark")

    def test_path_prefix_requires_a_segment_boundary(self):
        cookie = Cookie(host_only=False, name="p", value="1", domain="example.com",
                        path="/app")
        self.assertTrue(cookie.matches("http://example.com/app/x"))
        self.assertFalse(cookie.matches("http://example.com/application"))

    def test_secure_is_https_only(self):
        cookie = Cookie(name="s", value="1", domain="example.com", secure=True)
        self.assertFalse(cookie.matches("http://example.com/"))
        self.assertTrue(cookie.matches("https://example.com/"))

    def test_expiry(self):
        cookie = Cookie(name="e", value="1", domain="example.com", expires=1.0)
        self.assertFalse(cookie.matches("http://example.com/"))

    def test_longer_path_is_sent_first(self):
        jar = CookieJar()
        jar.update_from_response("http://example.com/", [("Set-Cookie", "a=root; Path=/")])
        jar.update_from_response("http://example.com/", [("Set-Cookie", "a=deep; Path=/x")])
        self.assertEqual(jar.header_for("http://example.com/x/y"), "a=deep; a=root")

    def test_add_raw(self):
        jar = CookieJar()
        names = jar.add_raw("https://target.tld/", "sid=1; theme=dark; broken")
        self.assertEqual(names, ["sid", "theme"])
        self.assertEqual(jar.header_for("https://target.tld/page"), "sid=1; theme=dark")

    def test_cdp_export(self):
        jar = CookieJar()
        jar.update_from_response("https://a.example/", [("Set-Cookie", "sid=abc; Path=/")])
        exported = jar.cdp_cookies()
        self.assertEqual(exported[0]["url"], "https://a.example/")
        self.assertEqual(exported[0]["name"], "sid")
        jar.update_from_response("http://plain.example/", [("Set-Cookie", "theme=dark")])
        urls = {c["name"]: c["url"] for c in jar.cdp_cookies()}
        self.assertEqual(urls["theme"], "http://plain.example/")
        self.assertEqual(urls["sid"], "https://a.example/")

    def test_netscape_round_trip(self):
        jar = CookieJar()
        jar.update_from_response("http://a.example/",
                                 [("Set-Cookie", "sid=abc; Path=/; Max-Age=3600"),
                                  ("Set-Cookie", "theme=dark")])
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            jar.save_netscape(path)
            loaded = CookieJar()
            self.assertEqual(loaded.load_netscape(path), 2)
            self.assertEqual(loaded.names(), ["sid", "theme"])
            self.assertEqual(loaded.header_for("http://a.example/"), "sid=abc; theme=dark")
        finally:
            os.unlink(path)

    def test_describe_never_shows_values(self):
        jar = CookieJar()
        jar.update_from_response("http://a.example/", [("Set-Cookie", "sid=supersecret")])
        self.assertIn("sid", jar.describe())
        self.assertNotIn("supersecret", jar.describe())


LOGIN_PAGE = """<html><body>
<form action="/login" method="POST">
  <input type="hidden" name="csrf_token" value="tok-1">
  <input name="username" type="text">
  <input name="password" type="password">
  <button type="submit">go</button>
</form></body></html>"""

ACCOUNT_PAGE = """<html><body><h1>Welcome</h1>
<form action="/account" method="POST">
  <input type="hidden" name="csrf_token" value="tok-2">
  <input name="comment">
</form></body></html>"""


class FakeResponse:
    def __init__(self, url, status=200, text="", ctype="text/html"):
        self.url = url
        self.status = status
        self.text = text
        self.is_html = ctype == "text/html"


class FakeHTTP:
    """Minimal stand-in for xssmap.net.HTTP that records the login POST."""

    def __init__(self, pages, login_response, set_cookie="sid=sess-1; Path=/"):
        self.pages = pages
        self.login_response = login_response
        self.set_cookie = set_cookie
        self.posts = []
        self.jar = CookieJar()

    def get(self, url, allow_redirects=True):
        return self.pages.get(url, FakeResponse(url, 404, "<h1>missing</h1>"))

    def post(self, url, body, headers=None, allow_redirects=True):
        self.posts.append((url, body, headers))
        if self.set_cookie:
            self.jar.update_from_response(url, [("Set-Cookie", self.set_cookie)])
        return self.login_response


class LoginFlow(unittest.TestCase):
    def test_successful_login_sets_cookie_and_reuses_hidden_token(self):
        http = FakeHTTP(
            pages={"http://t/login": FakeResponse("http://t/login", text=LOGIN_PAGE)},
            login_response=FakeResponse("http://t/account", text=ACCOUNT_PAGE))
        result = Session(http).login("http://t/login", "alice", "s3cret")
        self.assertTrue(result.ok, result.describe())
        self.assertIn("sid", result.cookie_names)
        self.assertIn("sid", result.describe())
        self.assertNotIn("sess-1", result.describe())
        url, body, _headers = http.posts[0]
        self.assertEqual(url, "http://t/login")
        text = body.decode()
        self.assertIn("csrf_token=tok-1", text)
        self.assertIn("username=alice", text)
        self.assertIn("password=s3cret", text)

    def test_failure_message_is_reported(self):
        http = FakeHTTP(
            pages={"http://t/login": FakeResponse("http://t/login", text=LOGIN_PAGE)},
            login_response=FakeResponse(
                "http://t/login", status=200,
                text=LOGIN_PAGE.replace("</form>", "</form><p>Invalid username or password</p>")),
            set_cookie="")
        result = Session(http).login("http://t/login", "alice", "wrong")
        self.assertFalse(result.ok)
        self.assertTrue(result.confident)
        self.assertIn("failure", result.reason)

    def test_401_is_a_confident_failure(self):
        http = FakeHTTP(
            pages={"http://t/login": FakeResponse("http://t/login", text=LOGIN_PAGE)},
            login_response=FakeResponse("http://t/login", status=401, text="nope"),
            set_cookie="")
        result = Session(http).login("http://t/login", "alice", "wrong")
        self.assertFalse(result.ok)
        self.assertIn("401", result.reason)

    def test_missing_form_is_reported_not_crashed(self):
        http = FakeHTTP(pages={"http://t/login": FakeResponse("http://t/login", text="<p>hi")},
                        login_response=FakeResponse("http://t/login"))
        result = Session(http).login("http://t/login", "a", "b")
        self.assertFalse(result.ok)
        self.assertIn("no login form", result.reason)

    def test_explicit_field_names_and_extra_data(self):
        page = LOGIN_PAGE.replace("name=\"username\"", "name=\"email\"")
        http = FakeHTTP(pages={"http://t/login": FakeResponse("http://t/login", text=page)},
                        login_response=FakeResponse("http://t/account", text=ACCOUNT_PAGE))
        Session(http).login("http://t/login", "a@b", "pw", user_field="email",
                            extra={"remember": "1"})
        body = http.posts[0][1].decode()
        self.assertIn("email=a%40b", body)
        self.assertIn("remember=1", body)


class CsrfHelpers(unittest.TestCase):
    def test_tokens_from_form_and_meta(self):
        page = LOGIN_PAGE + '<meta name="csrf-token" content="meta-1">'
        tokens = csrf_tokens(page)
        self.assertEqual(tokens.get("csrf_token"), "tok-1")
        self.assertEqual(tokens.get("csrf-token"), "meta-1")

    def test_login_form_detection(self):
        from xssmap.htmlparse import parse_page

        form = parse_page("http://t/login", LOGIN_PAGE).forms[0]
        self.assertTrue(is_login_form(form))
        account = parse_page("http://t/account", ACCOUNT_PAGE).forms[0]
        self.assertFalse(is_login_form(account))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ReloginTests(unittest.TestCase):
    """A long scan can outlive its session cookie; --verify needs a second login."""

    def _http(self, password="s3cret"):
        return FakeHTTP(
            pages={"http://t/login": FakeResponse("http://t/login", text=LOGIN_PAGE)},
            login_response=FakeResponse("http://t/account", text=ACCOUNT_PAGE))

    def test_no_stored_credentials_means_no_retry(self):
        http = self._http()
        session = Session(http)
        self.assertIsNone(session.relogin())
        self.assertEqual(session.relogins, 0)
        self.assertEqual(http.posts, [])

    def test_stored_credentials_are_submitted_again(self):
        http = self._http()
        session = Session(http)
        session.login("http://t/login", "alice", "s3cret")
        first = http.posts[0][1]
        result = session.relogin()
        self.assertTrue(result.ok, result.describe())
        self.assertEqual(session.relogins, 1)
        self.assertEqual(len(http.posts), 2)
        # The retry is the same form, not a new guess: one credential set only.
        self.assertEqual(http.posts[1][1], first)
        self.assertEqual(http.posts[1][1].decode().count("password="), 1)

    def test_a_failed_login_stores_nothing_to_retry(self):
        http = FakeHTTP(
            pages={"http://t/login": FakeResponse("http://t/login", text=LOGIN_PAGE)},
            login_response=FakeResponse("http://t/login", status=401, text="nope"),
            set_cookie="")
        session = Session(http)
        session.login("http://t/login", "alice", "wrong")
        self.assertIsNone(session.credentials)
        self.assertIsNone(session.relogin())

    def test_credentials_are_not_part_of_the_login_report(self):
        http = self._http()
        session = Session(http)
        result = session.login("http://t/login", "alice", "s3cret")
        self.assertNotIn("s3cret", result.describe())
        self.assertIn("password", session.credentials)  # in-memory only
