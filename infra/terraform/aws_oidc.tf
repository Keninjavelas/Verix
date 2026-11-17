# ==============================================================================
# Verix Zero-Trust IaC — AWS OpenID Connect (OIDC) Identity Federation
# ==============================================================================
# Eliminates static IAM access keys (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
# by federating GitHub Actions OIDC JWT tokens directly with AWS STS.
# ==============================================================================

data "aws_caller_identity" "current" {}

# 1. GitHub Actions OIDC Identity Provider
resource "aws_iam_openid_connect_provider" "github_actions" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]

  tags = {
    Name = "verix-github-actions-oidc"
  }
}

# 2. Zero-Trust AssumeRole Trust Policy (Strict Audience + Branch/Repo Lock)
data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    sid     = "GitHubActionsOIDCMainBranchOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    # Prevent Confused Deputy attacks by verifying intended token audience
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Cryptographically bind role assumption to the exact repository and main branch
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:Keninjavelas/Verix:ref:refs/heads/main"]
    }
  }
}

# 3. Ephemeral GitHub Actions Execution Role (1-hour max STS token lifetime)
resource "aws_iam_role" "verix_github_actions_role" {
  name                 = "verix_github_actions_role"
  description          = "Credential-less OIDC role assumed by GitHub Actions on Keninjavelas/Verix main branch"
  assume_role_policy   = data.aws_iam_policy_document.github_actions_assume_role.json
  max_session_duration = 3600
}

# 4. Strictly Scoped Least-Privilege Policy (No AdministratorAccess / No Wildcards)
data "aws_iam_policy_document" "verix_github_actions_least_privilege" {
  # State Bucket Access (Scoped strictly to the Verix Terraform state bucket)
  statement {
    sid    = "TerraformRemoteStateS3Scoped"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketVersioning",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicy"
    ]
    resources = [
      "arn:aws:s3:::${var.tf_state_bucket}"
    ]
  }

  statement {
    sid    = "TerraformRemoteStateObjectReadWrite"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
    resources = [
      "arn:aws:s3:::${var.tf_state_bucket}/global/verix-ledger/*"
    ]
  }

  # State Lock Table Access (Scoped strictly to verix-terraform-lock)
  statement {
    sid    = "TerraformStateLockDynamoDBScoped"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.tf_lock_table}"
    ]
  }

  # Verix Ledger DynamoDB Table Management (Scoped strictly to verix-ledger-aws)
  statement {
    sid    = "VerixLedgerTableLifecycleScoped"
    effect = "Allow"
    actions = [
      "dynamodb:CreateTable",
      "dynamodb:DescribeTable",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:ListTagsOfResource",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
      "dynamodb:UpdateTable",
      "dynamodb:UpdateContinuousBackups"
    ]
    resources = [
      "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/verix-ledger-aws",
      "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/verix-ledger-aws/index/*"
    ]
  }
}

resource "aws_iam_policy" "verix_github_actions_policy" {
  name        = "verix-github-actions-least-privilege"
  description = "Least-privilege policy restricting GitHub Actions to Verix state and ledger tables"
  policy      = data.aws_iam_policy_document.verix_github_actions_least_privilege.json
}

resource "aws_iam_role_policy_attachment" "verix_github_actions_attach" {
  role       = aws_iam_role.verix_github_actions_role.name
  policy_arn = aws_iam_policy.verix_github_actions_policy.arn
}

output "aws_github_actions_role_arn" {
  description = "ARN of the AWS IAM Role assumed by GitHub Actions via OIDC"
  value       = aws_iam_role.verix_github_actions_role.arn
}
