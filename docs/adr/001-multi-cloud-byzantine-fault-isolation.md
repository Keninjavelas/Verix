# ADR-001: Multi-Cloud Byzantine Fault Isolation vs. Single-Cloud Architecture

- **Status:** Accepted
- **Date:** 2026-11-18
- **Deciders:** Verix Architecture & DevSecOps Engineering
- **Related Artifacts:**
  - [`infra/terraform/databases.tf`](../../infra/terraform/databases.tf)
  - [`infra/terraform/aws_compute.tf`](../../infra/terraform/aws_compute.tf)
  - [`infra/terraform/gcp_compute.tf`](../../infra/terraform/gcp_compute.tf)
  - [`src/ledger/chain.js`](../../src/ledger/chain.js)
  - [`src/nodes/replication.js`](../../src/nodes/replication.js)

---

## 1. Context & Threat Model

Autonomous AI agents are increasingly granted authority to provision infrastructure, execute financial transactions, and mutate production systems. When an incident or unauthorized execution occurs, forensic investigators rely on the execution audit log to determine:
1. Which agent identity signed the action envelope (`ML-DSA-65` / `SLH-DSA-SHA2-128F`).
2. Whether the action conformed to scoped policy at the timestamp of execution.
3. Whether any historical audit records were retroactively altered, deleted, or reordered.

In a **single-cloud architecture** (e.g., running solely on AWS with Amazon DynamoDB), the cloud provider's control plane represents a **Single Point of Trust and Failure**. If an adversary compromises an administrative IAM role within that single cloud account—or if a privileged insider mutates the underlying storage service—the attacker can rewrite historical records and recompute the hash chain within that single provider's boundary.

---

## 2. Decision

We architect Verix around **Multi-Cloud Byzantine Fault Isolation** across two independent hyperscalers (**AWS** and **Google Cloud Platform**) combined with **Control-Plane Append-Only IAM Enforcement**:

1. **Heterogeneous State Engines:**
   - **AWS Quorum Node (`verix-node-aws-1`):** Persists Merkle-chained execution proofs to **Amazon DynamoDB** (`verix-ledger-aws`, `PAY_PER_REQUEST`, Point-in-Time Recovery enabled, KMS encrypted) via private VPC Gateway Endpoints.
   - **GCP Quorum Node (`verix-node-gcp-1`):** Persists identical Merkle-chained execution proofs to **Google Cloud Firestore in Native Mode** (`verix-ledger-gcp`, multi-region `nam5`, PITR enabled, `DELETE_PROTECTION_ENABLED`).
2. **Control-Plane Append-Only Guarantee:**
   - The AWS Fargate runtime role (`verix-ecs-task-role`) is bound to `verix-aws-node-ledger-append-only`, which grants `dynamodb:PutItem`, `dynamodb:GetItem`, and `dynamodb:Query` while attaching an **explicit `Effect = "Deny"`** on `dynamodb:DeleteItem` and `dynamodb:DeleteTable`.
   - The GCP Cloud Run runtime service account (`verix-gcp-node-runtime`) is bound to the custom role `verixFirestoreLedgerAppendOnly`, which grants `datastore.entities.create`, `datastore.entities.get`, and `datastore.entities.list` while **omitting `datastore.entities.delete`**.
3. **Cryptographic Divergence Detection:**
   - Every proof requires signed witness attestations (`ML-DSA-65`) across the configured quorum (`Math.floor(N / 2) + 1`). During verification and continuous chain audits, Verix compares the SHA3-256 Merkle chain heads (`head.root` and `head.seq`) across AWS and GCP. Any single-cloud tampering immediately triggers a cross-cloud root divergence alert (`divergence.consistent = false`), capping the trust score in the quarantine band.

---

## 3. Consequences

### Positive
- **Byzantine Fault Tolerance Across Cloud Control Planes:** An attacker who achieves complete compromise of the AWS environment still cannot forge the GCP node's `ML-DSA-65` witness key (isolated in GCP Secret Manager under Cloud KMS CMEK) or erase records in Firestore.
- **Defense-in-Depth Immutability:** Immutability is enforced at three independent layers:
  1. *Cryptographic layer:* SHA3-256 Merkle hash chaining + FIPS 204 `ML-DSA-65` post-quantum signatures.
  2. *Database engine layer:* Conditional writes (`attribute_not_exists` in DynamoDB and `ref.create()` in Firestore).
  3. *Cloud IAM control plane:* Explicit removal/denial of delete permissions on runtime compute roles.
- **Survivor Availability:** Regional or provider-wide outages in one cloud do not destroy historical forensic evidence stored in the peer cloud.

### Negative / Trade-offs
- **Cross-Cloud Quorum Write Latency:** Synchronous witness certification across AWS (`us-east-1`) and GCP (`us-central1`) adds WAN round-trip latency (~25–45 ms) compared to a single-AZ local write.
- **Multi-Provider IaC Complexity:** Terraform state must orchestrate both `hashicorp/aws` and `hashicorp/google` providers, requiring dual OIDC/Workload Identity Federation in CI/CD pipelines.
