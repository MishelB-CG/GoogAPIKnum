import unittest

from googapi_knum.cli import (
    interpret_firebase_account_lookup,
    interpret_firebase_password_login,
    interpret_firebase_public_config,
    interpret_gemini_response,
)


class FakeResponse:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data
        self.content = b"{}"
        self.text = "{}"

    def json(self):
        return self._data


class InterpreterTests(unittest.TestCase):
    def test_gemini_permission_denied_is_rejected(self):
        resp = FakeResponse(403, {"error": {"status": "PERMISSION_DENIED", "message": "Permission denied"}})

        classification, _ = interpret_gemini_response(resp)

        self.assertEqual(classification, "REJECTED (permission denied)")

    def test_gemini_key_restriction_is_rejected(self):
        resp = FakeResponse(403, {"error": {"status": "PERMISSION_DENIED", "message": "API_KEY_SERVICE_BLOCKED"}})

        classification, _ = interpret_gemini_response(resp)

        self.assertEqual(classification, "REJECTED (blocked by key API restrictions)")

    def test_firebase_public_config_returns_project_context(self):
        resp = FakeResponse(200, {"projectId": "demo-app", "authorizedDomains": ["localhost"]})

        classification, detail, data = interpret_firebase_public_config(resp)

        self.assertEqual(classification, "ACCEPTED (public config exposed)")
        self.assertIn("projectId=demo-app", detail)
        self.assertEqual(data["projectId"], "demo-app")

    def test_firebase_password_login_expected_error_means_endpoint_reachable(self):
        resp = FakeResponse(400, {"error": {"message": "EMAIL_NOT_FOUND"}})

        classification, _, _ = interpret_firebase_password_login(resp)

        self.assertEqual(classification, "ACCEPTED (password login endpoint reachable)")

    def test_firebase_lookup_invalid_token_means_endpoint_reachable(self):
        resp = FakeResponse(400, {"error": {"message": "INVALID_ID_TOKEN"}})

        classification, _, _ = interpret_firebase_account_lookup(resp)

        self.assertEqual(classification, "ACCEPTED (lookup endpoint reachable; valid user token required)")


if __name__ == "__main__":
    unittest.main()
