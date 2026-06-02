#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-STOR-006 — Storage Account Blob Soft Delete Disabled
# Usage: ./fix_az_stor_006.sh <resource-group> <storage-account-name> [retention-days]
# Severity: MEDIUM

set -euo pipefail

RESOURCE_GROUP=$1
RESOURCE_NAME=$2
RETENTION_DAYS=${3:-7}

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name> [retention-days]"
  exit 1
fi

echo "Enabling blob soft delete (retention days: $RETENTION_DAYS) on storage account: $RESOURCE_NAME"

az storage account blob-service-properties update \
  --account-name "$RESOURCE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-delete-retention true \
  --delete-retention-days "$RETENTION_DAYS"

echo "✅ Remediation complete for $RESOURCE_NAME — blob soft delete has been enabled."
