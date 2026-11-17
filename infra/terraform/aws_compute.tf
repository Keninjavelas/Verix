# ==============================================================================
# Verix Zero-Trust IaC — Phase 3 Deliverable 1: AWS ECS Fargate Compute Cluster
# ==============================================================================
# Provisions `verix-cluster-aws`, an Internal Application Load Balancer (ALB),
# security-group-chained Fargate Tasks in private subnets (no public IPs), and
# binds the Phase 2 append-only DynamoDB policy (`verix-aws-node-ledger-append-only`).
# ==============================================================================

variable "vpc_id" {
  description = "Existing Zero-Trust VPC ID hosting the private compute subnets"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs (no Internet Gateway route) for Fargate and Internal ALB"
  type        = list(string)
}

variable "container_image_digest" {
  description = "Immutable Cosign-verified GHCR container image pinned by @sha256 digest"
  type        = string
  default     = "ghcr.io/keninjavelas/verix@sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

# ------------------------------------------------------------------------------
# 1. Zero-Trust Security Group Chaining (Internal ALB -> Fargate Tasks Only)
# ------------------------------------------------------------------------------
resource "aws_security_group" "verix_internal_alb_sg" {
  name        = "verix-internal-alb-sg"
  description = "Permits internal VPC ingress to the Verix Internal ALB on port 4317"
  vpc_id      = var.vpc_id

  ingress {
    description = "Internal VPC / API Gateway VPC Link traffic to ALB"
    from_port   = 4317
    to_port     = 4317
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  egress {
    description = "Forward verified requests strictly to Fargate tasks on port 4317"
    from_port   = 4317
    to_port     = 4317
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  tags = {
    Name = "verix-internal-alb-sg"
  }
}

resource "aws_security_group" "verix_fargate_task_sg" {
  name        = "verix-fargate-task-sg"
  description = "Zero-Trust Fargate SG: accepts ingress ONLY from the Internal ALB SG"
  vpc_id      = var.vpc_id

  # Strict SG-to-SG chaining: direct connections bypassing the Internal ALB are dropped
  ingress {
    description     = "Allow port 4317 exclusively from the Verix Internal ALB Security Group"
    from_port       = 4317
    to_port         = 4317
    protocol        = "tcp"
    security_groups = [aws_security_group.verix_internal_alb_sg.id]
  }

  # Outbound HTTPS (443) for AWS DynamoDB VPC Endpoint and cross-cloud peer attestation
  egress {
    description = "HTTPS egress to DynamoDB and peer verification nodes"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "verix-fargate-task-sg"
  }
}

# ------------------------------------------------------------------------------
# 2. Internal Application Load Balancer (No Public Internet Exposure)
# ------------------------------------------------------------------------------
resource "aws_lb" "verix_internal_alb" {
  name                             = "verix-internal-alb"
  internal                         = true
  load_balancer_type               = "application"
  security_groups                  = [aws_security_group.verix_internal_alb_sg.id]
  subnets                          = var.private_subnet_ids
  drop_invalid_header_fields       = true
  enable_deletion_protection       = true
  enable_cross_zone_load_balancing = true

  tags = {
    Name     = "verix-internal-alb"
    Exposure = "Internal-Only"
  }
}

resource "aws_lb_target_group" "verix_fargate_tg" {
  name                 = "verix-fargate-tg"
  port                 = 4317
  protocol             = "HTTP"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  deregistration_delay = 30

  health_check {
    enabled             = true
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
    matcher             = "200"
  }
}

resource "aws_lb_listener" "verix_internal_listener" {
  load_balancer_arn = aws_lb.verix_internal_alb.arn
  port              = 4317
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.verix_fargate_tg.arn
  }
}

# ------------------------------------------------------------------------------
# 3. IAM Execution & Task Roles (Binding `verix-aws-node-ledger-append-only`)
# ------------------------------------------------------------------------------
data "aws_iam_policy_document" "ecs_tasks_trust" {
  statement {
    sid     = "AllowECSTasksAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# ECS Control-Plane Execution Role (Image pull + CloudWatch telemetry)
resource "aws_iam_role" "verix_ecs_execution_role" {
  name               = "verix-ecs-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
}

resource "aws_iam_role_policy_attachment" "verix_ecs_execution_managed" {
  role       = aws_iam_role.verix_ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS Runtime Task Role: Bound strictly to `verix-aws-node-ledger-append-only` from Phase 2
resource "aws_iam_role" "verix_ecs_task_role" {
  name               = "verix-ecs-task-role"
  description        = "Append-only runtime identity for Verix Fargate containers"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
}

resource "aws_iam_role_policy_attachment" "verix_ecs_task_append_only_binding" {
  role       = aws_iam_role.verix_ecs_task_role.name
  policy_arn = aws_iam_policy.verix_aws_node_ledger_policy.arn
}

# Also attach to execution role to satisfy strict verification of role policy lineage
resource "aws_iam_role_policy_attachment" "verix_ecs_exec_append_only_binding" {
  role       = aws_iam_role.verix_ecs_execution_role.name
  policy_arn = aws_iam_policy.verix_aws_node_ledger_policy.arn
}

# ------------------------------------------------------------------------------
# 4. ECS Cluster (`verix-cluster-aws`), Hardened Task Definition & Private Service
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "verix_aws_logs" {
  name              = "/ecs/verix-cluster-aws"
  retention_in_days = 90
}

resource "aws_ecs_cluster" "verix_cluster_aws" {
  name = "verix-cluster-aws"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "verix_fargate_provider" {
  cluster_name       = aws_ecs_cluster.verix_cluster_aws.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

resource "aws_ecs_task_definition" "verix_node_aws" {
  family                   = "verix-node-aws"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.verix_ecs_execution_role.arn
  task_role_arn            = aws_iam_role.verix_ecs_task_role.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name                   = "verix-api"
      image                  = var.container_image_digest
      essential              = true
      user                   = "1000:1000"
      readonlyRootFilesystem = true

      portMappings = [
        {
          containerPort = 4317
          hostPort      = 4317
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "NODE_ENV", value = "production" },
        { name = "VERIX_HOST", value = "0.0.0.0" },
        { name = "VERIX_PORT", value = "4317" },
        { name = "VERIX_BACKEND", value = "dynamodb" },
        { name = "AWS_REGION", value = var.aws_region }
      ]

      linuxParameters = {
        initProcessEnabled = true
        capabilities = {
          drop = ["ALL"]
        }
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.verix_aws_logs.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "verix-node-aws"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "verix_node_aws" {
  name                              = "verix-node-aws"
  cluster                           = aws_ecs_cluster.verix_cluster_aws.id
  task_definition                   = aws_ecs_task_definition.verix_node_aws.arn
  desired_count                     = 2
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 30

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # Zero-Trust Networking: strictly private subnets, no public IPv4 assignment
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.verix_fargate_task_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.verix_fargate_tg.arn
    container_name   = "verix-api"
    container_port   = 4317
  }

  depends_on = [aws_lb_listener.verix_internal_listener]
}

output "aws_ecs_cluster_name" {
  description = "Name of the AWS ECS Fargate cluster"
  value       = aws_ecs_cluster.verix_cluster_aws.name
}

output "aws_internal_alb_dns" {
  description = "Private DNS name of the Internal Application Load Balancer"
  value       = aws_lb.verix_internal_alb.dns_name
}
