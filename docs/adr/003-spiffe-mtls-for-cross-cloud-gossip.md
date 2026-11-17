# ADR-003: TLS 1.3 SPIFFE mTLS vs. Shared API Keys for Cross-Cloud Node Gossip

- **Status:** Accepted
- **Date:** 2026-11-18
- **Deciders:** Verix Architecture & DevSecOps Engineering
- **Related Artifacts:**
  - [`infra/terraform/secrets_and_mtls.tf`](../../infra/terraform/secrets_and_mtls.tf)
  - [`src/security/mtls.js`](../../src/security/mtls.js)
  - [`src/nodes/gossip.js`](../../src/nodes/gossip.js)

---

## 1. Context & Threat Model

To commit an execution proof to the distributed Verix ledger, the coordinator node must exchange certification (`POST /nodes/:nodeId/certify`), acceptance (`POST /nodes/:nodeId/accept`), and event replication (`POST /events/ingest`) messages with witness nodes running in remote cloud providers (AWS ECS Fargate <-> GCP Cloud Run).

In prototype environments, peer-to-peer node authentication often relies on a shared static bearer token (`Authorization: Bearer <VERIX_NODE_TOKEN>`) over standard one-way TLS. In a production multi-cloud deployment, relying solely on bearer tokens fails Zero-Trust requirements:
1. **Symmetric Shared Secret Blast Radius:** If a shared bearer token is compromised on a single node, an attacker can impersonate *any* node in the quorum fleet.
2. **Lack of Transport-Layer Mutual Authentication:** Standard one-way TLS authenticates only the server's DNS hostname—the server accepts TCP/TLS handshakes from any client before HTTP application middleware ever inspects the `Authorization` header.
3. **Ephemeral IP Addresses in Serverless Compute:** AWS Fargate tasks and GCP Cloud Run instances scale dynamically and cannot rely on static IP allowlists for peer identity.

---

## 2. Decision

We enforce **TLS 1.3 Mutual TLS (mTLS)** with **SPIFFE URI Subject Alternative Name (SAN) Identity Pinning** and **Customer-Managed KMS Secret Storage**:

1. **Internal ECDSA P-384 PKI & Short-Lived Leaf Certificates (`secrets_and_mtls.tf`):**
   - Provisioned an internal Verix Root CA using `ECDSA P-384`.
   - Issued short-lived (30-day validity, `720h`) leaf certificates configured for both `server_auth` and `client_auth`, embedding explicit **SPIFFE IDs** in the X.509 URI Subject Alternative Name extension:
     - AWS Node: `spiffe://verix.internal/ns/prod/node/verix-node-aws-1`
     - GCP Node: `spiffe://verix.internal/ns/prod/node/verix-node-gcp-1`
2. **Hardware-Backed KMS Envelope Storage:**
   - Each node's mTLS private key and PQC `ML-DSA-65` seed material are stored in **AWS Secrets Manager** (encrypted under Customer-Managed Key `aws_kms_key.verix_pqc_cmk` with 90-day rotation) and **GCP Secret Manager** (encrypted under Cloud KMS CMEK `google_kms_crypto_key.verix_pqc_cmek` with 90-day rotation).
   - Resource-level IAM policies ensure `verix-node-aws-1` cannot read `verix-node-gcp-1`'s private key and vice versa.
3. **Runtime TLS 1.3 & SPIFFE Handshake Verification (`src/security/mtls.js`):**
   - `buildMtlsServerOptions()` locks the transport protocol strictly to **TLS 1.3** (`minVersion: 'TLSv1.3'`, `maxVersion: 'TLSv1.3'`), restricts cipher suites to `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`, and enforces `requestCert: true` and `rejectUnauthorized: true`.
   - `verifyPeerSpiffeIdentity()` inspects the peer's raw X.509 certificate via `node:crypto` `X509Certificate`, extracts the `URI:spiffe://verix.internal/ns/prod/node/<nodeId>` SAN, validates `<nodeId>` against the authorized quorum roster, and supports SHA-256 certificate fingerprint pinning (`fingerprint256`).

---

## 3. Consequences

### Positive
- **Cryptographic Workload Identity Independent of Network Topology:** Serverless Fargate and Cloud Run instances prove their exact node identity (`verix-node-aws-1` vs. `verix-node-gcp-1`) cryptographically during the TLS 1.3 handshake regardless of dynamic IP allocation.
- **Zero-Trust Rejection Before HTTP Parsing:** Unauthorized clients without a valid ECDSA P-384 client certificate signed by the Verix Root CA are terminated during the TLS handshake before reaching the Node.js HTTP parser.
- **Defense-in-Depth with Application-Layer PQC:** Even over an authenticated TLS 1.3 mTLS channel, every quorum attestation payload remains individually signed using post-quantum `ML-DSA-65` and sealed via `ML-KEM-768` (`src/nodes/replication.js`), protecting data in transit against both classical MitM attacks and Harvest-Now-Decrypt-Later (HNDL) quantum threats.

### Negative / Trade-offs
- **Certificate Lifecycle Management:** Short-lived (30-day) leaf certificates require automated renewal via Terraform/PKI rotation workflows and secret version reloads in ECS Fargate and Cloud Run.
- **Handshake CPU Overhead:** Mutual X.509 verification adds initial handshake overhead, mitigated in `createMtlsPeerAgent()` (`src/security/mtls.js`) via persistent TLS 1.3 connection pooling (`keepAlive: true`).
