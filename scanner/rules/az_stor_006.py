"""AZ-STOR-006: Storage account allows soft delete disabled for blobs."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-STOR-006"
RULE_NAME = "Storage Account Blob Soft Delete Disabled"
SEVERITY = "MEDIUM"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "3.6",
    "NIST": "PR.IP-4",
    "ISO27001": "A.12.3.1",
    "SOC2": "A1.2",
}
DESCRIPTION = (
    "The storage account has blob soft delete disabled. Soft delete protects blob "
    "data from being permanently deleted by accident or malicious activity. When "
    "disabled, any deleted blob is immediately and permanently erased, leaving no "
    "opportunity for recovery."
)
REMEDIATION = (
    "Enable blob soft delete on the storage account with a retention period of "
    "at least 7 days. Navigate to Storage Account > Data management > Data protection, "
    "check 'Enable soft delete for blobs', and set the retention period."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_006.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect storage accounts with blob soft delete disabled."""
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        parsed = azure_client.parse_resource_id(account.id)
        rg = parsed.get("resource_group", "")
        if not rg:
            continue

        props = azure_client.get_storage_blob_service_properties(rg, account.name)
        if props is None:
            # Cannot determine soft delete status — skip to avoid false positives
            logger.warning(
                "az_stor_006: skipping %s — get_storage_blob_service_properties "
                "returned empty (permission or API failure)",
                account.name,
            )
            continue

        delete_retention_policy = getattr(props, "delete_retention_policy", None)
        is_enabled = False
        if delete_retention_policy:
            is_enabled = getattr(delete_retention_policy, "enabled", False)

        if not is_enabled:
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": account.id,
                "resource_name": account.name,
                "resource_type": "Microsoft.Storage/storageAccounts",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": rg,
                    "location": getattr(account, "location", ""),
                },
            })

    return findings
