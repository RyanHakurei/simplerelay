import unittest

from backend.services.smtp_access import (
    client_can_send,
    provider_for_sender,
    sasl_username_matches,
)

HOST = "relay.example.com"


class SaslUsernameTests(unittest.TestCase):
    def test_exact_username(self):
        self.assertTrue(sasl_username_matches("app", "app", HOST))

    def test_realm_suffix_matches_simple_username(self):
        self.assertTrue(sasl_username_matches("app@relay.example.com", "app", HOST))

    def test_other_realm_does_not_match(self):
        self.assertFalse(sasl_username_matches("app@other.example", "app", HOST))

    def test_email_username_does_not_match_local_part(self):
        self.assertFalse(sasl_username_matches("user", "user@domain.com", HOST))
        self.assertTrue(sasl_username_matches("user@domain.com", "user@domain.com", HOST))

    def test_blank_login_does_not_match(self):
        self.assertFalse(sasl_username_matches("", "app", HOST))
        self.assertFalse(sasl_username_matches("app", "", HOST))


class SenderBindingTests(unittest.TestCase):
    def setUp(self):
        self.providers = [
            {"id": 1, "email": "hve@contoso.com", "domain_routing": False, "user_id": 7},
            {"id": 2, "email": "catch@contoso.com", "domain_routing": True, "user_id": 7},
            {"id": 3, "email": "other@elsewhere.com", "domain_routing": False, "user_id": 8},
        ]
        self.clients = [
            {"smtp_username": "app", "provider_id": 1, "user_id": 7},
            {"smtp_username": "shared", "provider_id": None, "user_id": 7},
            {"smtp_username": "other", "provider_id": 3, "user_id": 8},
        ]

    def test_exact_provider_wins_over_domain_routing(self):
        provider = provider_for_sender("hve@contoso.com", self.providers)
        self.assertEqual(provider["id"], 1)

    def test_domain_routing_for_other_addresses(self):
        provider = provider_for_sender("someone@contoso.com", self.providers)
        self.assertEqual(provider["id"], 2)

    def test_login_must_belong_to_that_provider(self):
        provider = provider_for_sender("hve@contoso.com", self.providers)
        self.assertTrue(client_can_send("app", HOST, provider, self.clients))
        self.assertFalse(client_can_send("other", HOST, provider, self.clients))

    def test_user_wide_login_can_send_for_that_user(self):
        provider = provider_for_sender("someone@contoso.com", self.providers)
        self.assertTrue(client_can_send("shared", HOST, provider, self.clients))

    def test_other_users_login_cannot_send(self):
        provider = provider_for_sender("other@elsewhere.com", self.providers)
        self.assertFalse(client_can_send("app", HOST, provider, self.clients))
        self.assertFalse(client_can_send("shared", HOST, provider, self.clients))

    def test_missing_login_is_denied(self):
        provider = provider_for_sender("hve@contoso.com", self.providers)
        self.assertFalse(client_can_send("", HOST, provider, self.clients))
        self.assertFalse(client_can_send("app", HOST, None, self.clients))


if __name__ == "__main__":
    unittest.main()
