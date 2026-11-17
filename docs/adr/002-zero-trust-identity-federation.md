# ADR-002: Zero-Trust Identity Federation (OIDC / WIF) vs. Static IAM Credentials

- **Status:** Accepted
- **Date:** 2026-11-18
- **Deciders:** Verix Architecture & DevSecOps Engineering
- **Related Artifacts:**
  - [`infra/terraform/aws_oidc.tf`](../../infra/terraform/aws_oidc.tf)
  - [`infra/terraform/gcp_wif.tf`](../../infra/terraform/gcp_wif.tf)
  - [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
  - [`.github/workflows/cd.yml`](../../.github/workflows/cd.yml)
  - [`.github/workflows/ui_cd.yml`](../../.github/workflows/ui_cd.yml)

---

## 1. Context & Threat Model

Continuous Integration and Continuous Deployment (CI/CD) pipelines require privileged access to cloud control planes to reconcile Terraform state, push container images, and trigger serverless rollouts on AWS ECS Fargate and GCP Cloud Run.

Historically, engineering teams stored long-lived static credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and GCP Service Account JSON private keys) inside CI secret stores. For a Zero-Trust cryptographic audit platform, static credentials introduce unacceptable supply-chain risks:
1. **No Expiration by Default:** An exfiltrated IAM access key or GCP JSON key remains valid indefinitely until manually rotated or revoked.
2. **Lack of Cryptographic Call-Site Binding:** Static keys can be replayed from any IP address or workstation if leaked via build logs, malicious third-party GitHub Actions, or developer machine compromise.
3. **Over-Privileged Blast Radius:** Static CI keys are frequently granted broad `AdministratorAccess` or `roles/editor` permissions across the entire cloud account.

---

## 2. Decision

We strictly prohibit static cloud credentials across the entire Verix lifecycle and enforce **Ephemeral OpenID Connect (OIDC) Federation** paired with **Sigstore Keyless Artifact Attestation**:

1. **GitHub Actions -> AWS STS (`aws_oidc.tf`):**
   - Provisioned an `aws_iam_openid_connect_provider` for `https://token.actions.githubusercontent.com`.
   - Configured `verix_github_actions_role` (`max_session_duration = 3600`) with a dual-condition trust policy:
     - `StringEquals` on `token.actions.githubusercontent.com:aud = "sts.amazonaws.com"` (mitigating Confused Deputy token replay).
     - `StringLike` on `token.actions.githubusercontent.com:sub = "repo:Keninjavelas/Verix:ref:refs/heads/main"` (cryptographically restricting role assumption exclusively to commits on the `main` branch of `Keninjavelas/Verix`).
2. **GitHub Actions -> GCP Workload Identity Federation (`gcp_wif.tf`):**
   - Provisioned `google_iam_workload_identity_pool` (`verix-github-pool`) and `google_iam_workload_identity_pool_provider` (`verix-github-provider`).
   - Enforced a Common Expression Language (CEL) `attribute_condition` (`assertion.repository == 'Keninjavelas/Verix' && assertion.ref == 'refs/heads/main'`) evaluated at the Google Cloud STS ingress boundary before IAM evaluation even occurs.
3. **Keyless Container Signing (`ci.yml` & `cd.yml`):**
   - Container digests (`@sha256`) and CycloneDX SBOMs (`verix-sbom.cdx.json`) are signed and verified using **Sigstore Cosign** keyless OIDC certificates bound to `https://github.com/Keninjavelas/Verix/.github/workflows/ci.yml@refs/heads/main`.

---

## 3. Consequences

### Positive
- **Zero Static Secrets to Rotate or Leak:** Neither GitHub Secrets nor developer environments hold long-lived AWS access keys, GCP JSON keys, or Cosign private signing keys.
- **Branch-Level Cryptographic Isolation:** Pull requests from forks or unmerged feature branches cannot mint OIDC JWTs matching `ref:refs/heads/main`, mathematically preventing untrusted code from assuming production deployment roles.
- **End-to-End SLSA Provenance:** The CD pipeline (`cd.yml`) verifies the OIDC-backed Sigstore certificate on the exact `@sha256` image digest prior to invoking `terraform apply`, closing the gap between CI build and production execution.

### Negative / Trade-offs
- **Bootstrap Dependency:** Initial creation of the OIDC provider and state backend (`bootstrap-state.sh`) must be executed once via an authenticated bootstrap session before automated pipelines can assume the federated roles.
- **Strict Claim Debugging:** Any mismatch in repository casing, branch ref naming, or OIDC audience immediately rejects token exchange at the STS boundary.
