"""Smoke tests for the classroom demo."""

import unittest

from backend.app import app, init_db


class ThreatOpsSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def login(self, username="rajeshKumar", password="ADM123"):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )

    def csrf_token(self):
        with self.client.session_transaction() as sess:
            return sess.get("_csrf_token")

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_login_and_pages(self):
        response = self.login()
        self.assertEqual(response.status_code, 302)
        for path in ["/dashboard", "/analytics", "/visualize", "/alerts", "/sql_panel"]:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_sql_panel_allows_admin_select(self):
        self.login()
        response = self.client.post(
            "/run_query",
            json={"query": "SELECT 1 AS ok"},
            headers={"X-CSRF-Token": self.csrf_token()},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["rows"][0]["ok"], 1)

    def test_read_only_role_rejects_write_query(self):
        self.login("amitPatel", "ANLST123")
        response = self.client.post(
            "/run_query",
            json={"query": "DELETE FROM RAW_LOGS"},
            headers={"X-CSRF-Token": self.csrf_token()},
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
