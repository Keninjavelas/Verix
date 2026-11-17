# ==============================================================================
# Verix Zero-Trust IaC — Phase 6 Deliverable 1: Vector Database & AI RAG Layer
# ==============================================================================
# Provisions an Amazon OpenSearch Serverless Vector Search collection encrypted
# under the Phase 4 Customer-Managed KMS Key (`verix_pqc_cmk`), isolated inside
# the private VPC via an AOSS VPC Endpoint, and locked down via Data Access
# Policies exclusively to the Phase 3 AWS Fargate runtime task role.
# ==============================================================================

# 1. Encryption Policy — Bound to Phase 4 KMS Customer-Managed Key (CMK)
resource "aws_opensearchserverless_security_policy" "verix_vector_encryption" {
  name        = "verix-vector-kms-encryption"
  type        = "encryption"
  description = "Enforces Customer-Managed KMS encryption for the Verix RAG vector store"

  policy = jsonencode({
    Rules = [
      {
        ResourceType = "collection"
        Resource     = ["collection/verix-proofs-vector"]
      }
    ]
    AWSOwnedKey = false
    KmsARN      = aws_kms_key.verix_pqc_cmk.arn
  })
}

# 2. Private VPC Endpoint for OpenSearch Serverless (No Public Internet Exposure)
resource "aws_opensearchserverless_vpc_endpoint" "verix_vector_vpce" {
  name               = "verix-vector-private-vpce"
  vpc_id             = var.vpc_id
  subnet_ids         = var.private_subnet_ids
  security_group_ids = [aws_security_group.verix_internal_alb_sg.id]
}

# 3. Network Security Policy — Strictly Private (allow_public = false)
resource "aws_opensearchserverless_security_policy" "verix_vector_network" {
  name        = "verix-vector-zero-trust-network"
  type        = "network"
  description = "Blocks public access; restricts vector collection strictly to the private VPC endpoint"

  policy = jsonencode([
    {
      Description = "Private VPC endpoint access only for Verix RAG Copilot"
      Rules = [
        {
          ResourceType = "collection"
          Resource     = ["collection/verix-proofs-vector"]
        }
      ]
      AllowFromPublic = false
      SourceVPCEs     = [aws_opensearchserverless_vpc_endpoint.verix_vector_vpce.id]
    }
  ])
}

# 4. OpenSearch Serverless Vector Search Collection (`verix-proofs-vector`)
resource "aws_opensearchserverless_collection" "verix_proofs_vector" {
  name             = "verix-proofs-vector"
  type             = "VECTORSEARCH"
  description      = "Immutable PQC proof embeddings for the Verix AI Trust Copilot RAG engine"
  standby_replicas = "ENABLED"

  depends_on = [
    aws_opensearchserverless_security_policy.verix_vector_encryption,
    aws_opensearchserverless_security_policy.verix_vector_network
  ]
}

# 5. Zero-Trust Data Access Policy — Scoped Exclusively to Fargate Task Role
resource "aws_opensearchserverless_access_policy" "verix_vector_fargate_only" {
  name        = "verix-vector-fargate-task-only"
  type        = "data"
  description = "Grants vector query and embedding write permissions exclusively to the Verix Fargate Task Role"

  policy = jsonencode([
    {
      Description = "Least-privilege RAG vector access for Verix Fargate runtime"
      Rules = [
        {
          ResourceType = "collection"
          Resource     = ["collection/verix-proofs-vector"]
          Permission = [
            "aoss:DescribeCollectionItems"
          ]
        },
        {
          ResourceType = "index"
          Resource     = ["index/verix-proofs-vector/*"]
          Permission = [
            "aoss:CreateIndex",
            "aoss:DescribeIndex",
            "aoss:ReadDocument",
            "aoss:WriteDocument"
          ]
        }
      ]
      Principal = [
        aws_iam_role.verix_ecs_task_role.arn
      ]
    }
  ])
}

# 6. Secure LLM API Gateway Credentials (CMK-Encrypted Secrets Manager Vault)
resource "aws_secretsmanager_secret" "verix_llm_gateway_credentials" {
  name                    = "verix/prod/copilot/llm-gateway-credentials"
  description             = "CMK-encrypted LLM inference proxy credentials for the Verix Trust Copilot"
  kms_key_id              = aws_kms_key.verix_pqc_cmk.arn
  recovery_window_in_days = 30
}

data "aws_iam_policy_document" "verix_ai_copilot_runtime_policy" {
  statement {
    sid    = "AllowOpenSearchServerlessVectorAPIAccess"
    effect = "Allow"
    actions = [
      "aoss:APIAccessAll"
    ]
    resources = [
      aws_opensearchserverless_collection.verix_proofs_vector.arn
    ]
  }

  statement {
    sid    = "AllowReadLLMCopilotSecretOnly"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = [
      aws_secretsmanager_secret.verix_llm_gateway_credentials.arn
    ]
  }
}

resource "aws_iam_policy" "verix_ai_copilot_policy" {
  name        = "verix-ai-copilot-rag-least-privilege"
  description = "Allows Verix Fargate tasks to query the AOSS vector collection and read LLM proxy secrets"
  policy      = data.aws_iam_policy_document.verix_ai_copilot_runtime_policy.json
}

resource "aws_iam_role_policy_attachment" "verix_ecs_task_ai_copilot_binding" {
  role       = aws_iam_role.verix_ecs_task_role.name
  policy_arn = aws_iam_policy.verix_ai_copilot_policy.arn
}

output "verix_vector_collection_endpoint" {
  description = "Private VPC endpoint URL for the Verix OpenSearch Serverless Vector Collection"
  value       = aws_opensearchserverless_collection.verix_proofs_vector.collection_endpoint
}
