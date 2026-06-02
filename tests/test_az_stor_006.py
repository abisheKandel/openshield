"""Unit tests for scanner/rules/az_stor_006.py."""

import unittest
from unittest.mock import MagicMock

from scanner.rules.az_stor_006 import scan, RULE_ID, RULE_NAME, SEVERITY


class MockStorageAccount:
    def __init__(self, id_val, name_val, location_val="eastus"):
        self.id = id_val
        self.name = name_val
        self.location = location_val


class MockDeleteRetentionPolicy:
    def __init__(self, enabled):
        self.enabled = enabled


class MockBlobServiceProperties:
    def __init__(self, enabled):
        self.delete_retention_policy = MockDeleteRetentionPolicy(enabled)


class TestAzStor006Rule(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()
        self.subscription_id = "test-subscription"

    def test_scan_finding_when_soft_delete_disabled(self):
        """Should generate a finding when blob soft delete is disabled."""
        account = MockStorageAccount(
            "/subscriptions/test-sub/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/myacc",
            "myacc",
        )
        self.client.get_storage_accounts.return_value = [account]
        self.client.parse_resource_id.return_value = {"resource_group": "my-rg", "name": "myacc"}
        
        # Properties with soft delete disabled
        props = MockBlobServiceProperties(enabled=False)
        self.client.get_storage_blob_service_properties.return_value = props

        findings = scan(self.client, self.subscription_id)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["rule_id"], RULE_ID)
        self.assertEqual(finding["rule_name"], RULE_NAME)
        self.assertEqual(finding["severity"], SEVERITY)
        self.assertEqual(finding["resource_name"], "myacc")
        self.assertEqual(finding["resource_id"], account.id)

    def test_scan_no_finding_when_soft_delete_enabled(self):
        """Should NOT generate a finding when blob soft delete is enabled."""
        account = MockStorageAccount(
            "/subscriptions/test-sub/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/myacc",
            "myacc",
        )
        self.client.get_storage_accounts.return_value = [account]
        self.client.parse_resource_id.return_value = {"resource_group": "my-rg", "name": "myacc"}
        
        # Properties with soft delete enabled
        props = MockBlobServiceProperties(enabled=True)
        self.client.get_storage_blob_service_properties.return_value = props

        findings = scan(self.client, self.subscription_id)

        self.assertEqual(len(findings), 0)

    def test_scan_skip_when_properties_none(self):
        """Should skip the account (no finding) if blob properties cannot be retrieved."""
        account = MockStorageAccount(
            "/subscriptions/test-sub/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/myacc",
            "myacc",
        )
        self.client.get_storage_accounts.return_value = [account]
        self.client.parse_resource_id.return_value = {"resource_group": "my-rg", "name": "myacc"}
        
        # Properties API returns None (e.g. error/permission issue)
        self.client.get_storage_blob_service_properties.return_value = None

        findings = scan(self.client, self.subscription_id)

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
