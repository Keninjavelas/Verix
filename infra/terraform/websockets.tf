# ==============================================================================
# Verix Zero-Trust IaC — Phase 6 Deliverable 2: Real-Time Streaming & Event Bus
# ==============================================================================
# Decouples synchronous `POST /verify-action` PQC verification from real-time UI
# topology streaming using a CMK-encrypted AWS EventBridge bus, a CMEK-encrypted
# GCP Pub/Sub topic, and a throttled AWS API Gateway v2 WebSocket API connected
# privately to Fargate via a VPC Link.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Multi-Cloud Asynchronous Event Buses (AWS EventBridge & GCP Pub/Sub)
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_event_bus" "verix_proof_event_bus" {
  name               = "verix-proof-event-bus"
  kms_key_identifier = aws_kms_key.verix_pqc_cmk.arn
}

resource "aws_cloudwatch_event_archive" "verix_proof_event_archive" {
  name             = "verix-proof-event-archive"
  event_source_arn = aws_cloudwatch_event_bus.verix_proof_event_bus.arn
  retention_days   = 90
}

# GCP Cloud Pub/Sub Topic (Encrypted with Phase 4 Cloud KMS CMEK)
resource "google_pubsub_topic" "verix_proof_events_gcp" {
  project                    = var.gcp_project_id
  name                       = "verix-proof-events-gcp"
  kms_key_name               = google_kms_crypto_key.verix_pqc_cmek.id
  message_retention_duration = "604800s" # 7-day immutable event replay window
}

resource "google_pubsub_subscription" "verix_proof_events_sub" {
  project                      = var.gcp_project_id
  name                         = "verix-proof-events-sub"
  topic                        = google_pubsub_topic.verix_proof_events_gcp.name
  ack_deadline_seconds         = 20
  retain_acked_messages        = true
  message_retention_duration   = "604800s"
  enable_exactly_once_delivery = true
}

resource "google_pubsub_topic_iam_member" "verix_gcp_runtime_publisher" {
  project = var.gcp_project_id
  topic   = google_pubsub_topic.verix_proof_events_gcp.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.verix_gcp_node_runtime.email}"
}

# ------------------------------------------------------------------------------
# 2. AWS API Gateway v2 WebSocket API & Private VPC Link
# ------------------------------------------------------------------------------
resource "aws_apigatewayv2_vpc_link" "verix_ws_private_link" {
  name               = "verix-ws-private-vpc-link"
  security_group_ids = [aws_security_group.verix_internal_alb_sg.id]
  subnet_ids         = var.private_subnet_ids
}

resource "aws_apigatewayv2_api" "verix_realtime_ws_api" {
  name                       = "verix-realtime-trust-topology-ws"
  protocol_type              = "WEBSOCKET"
  route_selection_expression = "$request.body.action"
  description                = "Streams real-time PQC proof verifications and anomaly events to the Verix UI"
}

resource "aws_apigatewayv2_integration" "verix_ws_alb_integration" {
  api_id             = aws_apigatewayv2_api.verix_realtime_ws_api.id
  integration_type   = "HTTP_PROXY"
  integration_uri    = aws_lb_listener.verix_internal_listener.arn
  integration_method = "ANY"
  connection_type    = "VPC_LINK"
  connection_id      = aws_apigatewayv2_vpc_link.verix_ws_private_link.id
}

resource "aws_apigatewayv2_route" "ws_connect" {
  api_id    = aws_apigatewayv2_api.verix_realtime_ws_api.id
  route_key = "$connect"
  target    = "integrations/${aws_apigatewayv2_integration.verix_ws_alb_integration.id}"
}

resource "aws_apigatewayv2_route" "ws_disconnect" {
  api_id    = aws_apigatewayv2_api.verix_realtime_ws_api.id
  route_key = "$disconnect"
  target    = "integrations/${aws_apigatewayv2_integration.verix_ws_alb_integration.id}"
}

resource "aws_apigatewayv2_route" "ws_default" {
  api_id    = aws_apigatewayv2_api.verix_realtime_ws_api.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.verix_ws_alb_integration.id}"
}

resource "aws_apigatewayv2_stage" "verix_ws_prod" {
  api_id      = aws_apigatewayv2_api.verix_realtime_ws_api.id
  name        = "prod"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit   = 500
    throttling_rate_limit    = 1000
    data_trace_enabled       = false
    detailed_metrics_enabled = true
  }
}

output "verix_websocket_stage_endpoint" {
  description = "Production wss:// endpoint for the Verix Visual Trust Intelligence UI"
  value       = aws_apigatewayv2_stage.verix_ws_prod.invoke_url
}
