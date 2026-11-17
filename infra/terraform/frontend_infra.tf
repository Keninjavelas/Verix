# ==============================================================================
# Verix Zero-Trust IaC — Phase 6 Deliverable 3: Visual Intelligence Edge CDN
# ==============================================================================
# Provisions a private S3 origin bucket, CloudFront Origin Access Control (OAC)
# with SigV4 request signing, AWS WAFv2 edge protection, and strict HTTP security
# response headers (CSP, HSTS, X-Frame-Options) for the Verix Visual Topology UI.
# ==============================================================================

# 1. Private S3 Origin Bucket (Zero Public Access)
resource "aws_s3_bucket" "verix_ui_origin" {
  bucket = "verix-visual-intelligence-ui-origin"
}

resource "aws_s3_bucket_public_access_block" "verix_ui_origin_block" {
  bucket                  = aws_s3_bucket.verix_ui_origin.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "verix_ui_origin_versioning" {
  bucket = aws_s3_bucket.verix_ui_origin.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "verix_ui_origin_sse" {
  bucket = aws_s3_bucket.verix_ui_origin.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# 2. CloudFront Origin Access Control (SigV4 Authenticated Origin Fetches)
resource "aws_cloudfront_origin_access_control" "verix_ui_oac" {
  name                              = "verix-ui-sigv4-oac"
  description                       = "Enforces SigV4 signing from CloudFront to private S3 UI origin"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# 3. Strict Zero-Trust HTTP Security Headers Policy (CSP, HSTS, Frame Deny)
resource "aws_cloudfront_response_headers_policy" "verix_zero_trust_headers" {
  name    = "verix-ui-zero-trust-security-headers"
  comment = "Enforces strict CSP, HSTS preload, X-Frame-Options DENY, and nosniff on all UI responses"

  security_headers_config {
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss://*.execute-api.${var.aws_region}.amazonaws.com; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self';"
      override                = true
    }

    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    content_type_options {
      override = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }
}

# 4. AWS WAFv2 WebACL (Edge DDoS & OWASP Top-10 Protection)
resource "aws_wafv2_web_acl" "verix_ui_waf" {
  name        = "verix-ui-edge-waf"
  description = "Protects the Verix Visual Trust Intelligence CDN against L7 floods and bad inputs"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "VerixUICommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitPerIP"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "VerixUIRateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "VerixUIEdgeWAF"
    sampled_requests_enabled   = true
  }
}

# 5. CloudFront Edge Distribution
resource "aws_cloudfront_distribution" "verix_ui_cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  web_acl_id          = aws_wafv2_web_acl.verix_ui_waf.arn

  origin {
    domain_name              = aws_s3_bucket.verix_ui_origin.bucket_regional_domain_name
    origin_id                = "verix-s3-private-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.verix_ui_oac.id
  }

  default_cache_behavior {
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = "verix-s3-private-origin"
    viewer_protocol_policy     = "redirect-to-https"
    compress                   = true
    cache_policy_id            = "658327ea-f89d-4fab-a63d-7e88639e58f6" # Managed-CachingOptimized
    response_headers_policy_id = aws_cloudfront_response_headers_policy.verix_zero_trust_headers.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }
}

# 6. S3 Bucket Policy — Allows GetObject Exclusively from CloudFront OAC ARN
data "aws_iam_policy_document" "verix_ui_s3_oac_only" {
  statement {
    sid       = "AllowCloudFrontServicePrincipalReadOnly"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.verix_ui_origin.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.verix_ui_cdn.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "verix_ui_origin_policy" {
  bucket = aws_s3_bucket.verix_ui_origin.id
  policy = data.aws_iam_policy_document.verix_ui_s3_oac_only.json
}

output "verix_ui_cloudfront_domain" {
  description = "HTTPS Edge domain serving the Verix Visual Trust Intelligence UI"
  value       = aws_cloudfront_distribution.verix_ui_cdn.domain_name
}
