#!/usr/bin/env bash
# ==============================================================================
# Verix Zero-Trust IaC — Idempotent Remote State Bootstrapper (AWS S3 + DynamoDB)
# ==============================================================================
# Provisions an encrypted, versioned, public-blocked S3 state bucket with TLS-only
# bucket policy enforcement and an on-demand DynamoDB state lock table.
# ==============================================================================

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
STATE_BUCKET="${VERIX_TF_STATE_BUCKET:-verix-tfstate-production}"
LOCK_TABLE="${VERIX_TF_LOCK_TABLE:-verix-terraform-lock}"

echo "[INFO] Verifying AWS caller identity..."
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
echo "[INFO] Authenticated against AWS Account: ${ACCOUNT_ID} (Region: ${AWS_REGION})"

# ------------------------------------------------------------------------------
# 1. Idempotent S3 State Bucket Provisioning & Hardening
# ------------------------------------------------------------------------------
if aws s3api head-bucket --bucket "${STATE_BUCKET}" 2>/dev/null; then
  echo "[OK] S3 state bucket '${STATE_BUCKET}' already exists."
else
  echo "[INFO] Creating S3 state bucket '${STATE_BUCKET}' in '${AWS_REGION}'..."
  if [ "${AWS_REGION}" = "us-east-1" ]; then
    aws s3api create-bucket \
      --bucket "${STATE_BUCKET}" \
      --region "${AWS_REGION}" >/dev/null
  else
    aws s3api create-bucket \
      --bucket "${STATE_BUCKET}" \
      --region "${AWS_REGION}" \
      --create-bucket-configuration LocationConstraint="${AWS_REGION}" >/dev/null
  fi
  echo "[OK] Created S3 bucket '${STATE_BUCKET}'."
fi

echo "[INFO] Enforcing PublicAccessBlock on '${STATE_BUCKET}'..."
aws s3api put-public-access-block \
  --bucket "${STATE_BUCKET}" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "[INFO] Enabling strict state versioning on '${STATE_BUCKET}'..."
aws s3api put-bucket-versioning \
  --bucket "${STATE_BUCKET}" \
  --versioning-configuration Status=Enabled

echo "[INFO] Enforcing default AES256 Server-Side Encryption (SSE-S3) on '${STATE_BUCKET}'..."
aws s3api put-bucket-encryption \
  --bucket "${STATE_BUCKET}" \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        },
        "BucketKeyEnabled": true
      }
    ]
  }'

echo "[INFO] Applying Zero-Trust TLS-only bucket policy on '${STATE_BUCKET}'..."
TLS_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${STATE_BUCKET}",
        "arn:aws:s3:::${STATE_BUCKET}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
EOF
)
aws s3api put-bucket-policy --bucket "${STATE_BUCKET}" --policy "${TLS_POLICY}"

# ------------------------------------------------------------------------------
# 2. Idempotent DynamoDB State Lock Table Provisioning
# ------------------------------------------------------------------------------
if aws dynamodb describe-table --table-name "${LOCK_TABLE}" --region "${AWS_REGION}" >/dev/null 2>&1; then
  echo "[OK] DynamoDB lock table '${LOCK_TABLE}' already exists."
else
  echo "[INFO] Creating DynamoDB state lock table '${LOCK_TABLE}'..."
  aws dynamodb create-table \
    --table-name "${LOCK_TABLE}" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --sse-specification Enabled=true \
    --region "${AWS_REGION}" >/dev/null

  echo "[INFO] Waiting for DynamoDB table '${LOCK_TABLE}' to reach ACTIVE state..."
  aws dynamodb wait table-exists --table-name "${LOCK_TABLE}" --region "${AWS_REGION}"
  echo "[OK] DynamoDB lock table '${LOCK_TABLE}' is ACTIVE."
fi

echo "[INFO] Enabling Point-in-Time Recovery (PITR) on '${LOCK_TABLE}'..."
aws dynamodb update-continuous-backups \
  --table-name "${LOCK_TABLE}" \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \
  --region "${AWS_REGION}" >/dev/null

echo "[SUCCESS] Zero-Trust Terraform remote state backend is bootstrapped and locked."
