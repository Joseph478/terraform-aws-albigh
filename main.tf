locals {
    is_ec2    = var.launch_type == "EC2"
    is_django = var.type_project == "django"
    app_port  = local.is_django ? 8000 : 80

    default_bucket_name_log = "alb-logs-${replace(lower(var.name_main), "_", "-")}-${var.account_id}"
    bucket_name_log         = coalesce(var.bucket_name_log, local.default_bucket_name_log)

    adopt_bucket = var.bucket_exists
    new_bucket   = !var.bucket_exists

    bucket_id  = local.adopt_bucket ? data.aws_s3_bucket.existing[0].id : aws_s3_bucket.bucket[0].id
    bucket_arn = local.adopt_bucket ? data.aws_s3_bucket.existing[0].arn : aws_s3_bucket.bucket[0].arn

    common_tags   = merge(var.tags, {
        ENV     = "PROD"
        SERVICE = upper(var.name_main)
    })

    default_ecs_user_data = <<-EOF
        #!/bin/bash
        echo ECS_CLUSTER=${var.name_cluster_ecs} >> /etc/ecs/ecs.config
        echo ECS_BACKEND_HOST= >> /etc/ecs/ecs.config
    EOF

    user_data_script = (
        var.user_data != null ? var.user_data :
        var.user_data_file != null ? file(var.user_data_file) :
        var.ecs_connect ? local.default_ecs_user_data : null
    )
}

# ─── S3 para logs del ALB ────────────────────────────────────────────────────

resource "aws_s3_bucket" "bucket" {
    count         = local.new_bucket ? 1 : 0
    bucket        = local.bucket_name_log
    force_destroy = true

    tags = merge(local.common_tags, {
        Name = "BucketLogs${var.name_main}terraform"
    })

    lifecycle {
        ignore_changes  = [tags["ORDEN"], tags["Name"]]
        prevent_destroy = false
    }
}

# Referencia de solo lectura a un bucket ya existente (bucket_exists = true).
# No lo crea ni lo destruye; los recursos de abajo lo actualizan/administran.
data "aws_s3_bucket" "existing" {
    count  = local.adopt_bucket ? 1 : 0
    bucket = local.bucket_name_log
}

resource "aws_s3_bucket_ownership_controls" "ownership_controls" {
    bucket = local.bucket_id
    rule {
        object_ownership = "BucketOwnerPreferred"
    }
}

resource "aws_s3_bucket_acl" "s3_bucket_acl" {
    depends_on = [aws_s3_bucket_ownership_controls.ownership_controls]
    bucket     = local.bucket_id
    acl        = "private"
}

resource "aws_s3_bucket_public_access_block" "public_access_block" {
    bucket = local.bucket_id

    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "versioning" {
    bucket = local.bucket_id
    versioning_configuration {
        status = "Enabled"
    }
}

# Permisos para ELB
data "aws_elb_service_account" "main" {}

data "aws_iam_policy_document" "logs_document" {
    statement {
        actions   = ["s3:PutObject"]
        resources = ["${local.bucket_arn}/*"]

        principals {
            type        = "AWS"
            identifiers = [data.aws_elb_service_account.main.id]
        }
    }
}

resource "aws_s3_bucket_policy" "logs_policy" {
    bucket = local.bucket_id
    policy = data.aws_iam_policy_document.logs_document.json
}

# ─── Security Groups ─────────────────────────────────────────────────────────

resource "aws_security_group" "security_group_alb" {
    name        = "sg_alb_${var.name_main}_security_group"
    description = "Allow inbound traffic to ALB"
    vpc_id      = var.vpc_id

    ingress {
        description = "Trafic HTTP from VPC"
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "Trafic HTTPS from VPC"
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port        = 0
        to_port          = 0
        protocol         = "-1"
        cidr_blocks      = ["0.0.0.0/0"]
        ipv6_cidr_blocks = ["::/0"]
    }

    tags = merge(local.common_tags, {
        Name = "security_group_alb_${var.name_main}"
    })

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

# Security group para instancias EC2 (launch_type = EC2) o tareas Fargate (launch_type = FARGATE)
resource "aws_security_group" "security_group_ec2" {
    name        = "sg_instance_${var.name_main}"
    description = local.is_ec2 ? "Allow inbound traffic to EC2 instances" : "Allow inbound traffic to Fargate tasks"
    vpc_id      = var.vpc_id

    dynamic "ingress" {
        for_each = local.is_django ? [] : [1]
        content {
            description     = "Trafic HTTP from ALB"
            from_port       = 80
            to_port         = 80
            protocol        = "tcp"
            security_groups = [aws_security_group.security_group_alb.id]
        }
    }

    dynamic "ingress" {
        for_each = local.is_django ? [1] : []
        content {
            description     = "Trafic Django (Gunicorn) from ALB"
            from_port       = 8000
            to_port         = 8000
            protocol        = "tcp"
            security_groups = [aws_security_group.security_group_alb.id]
        }
    }

    ingress {
        description     = "Trafic HTTPS from ALB"
        from_port       = 443
        to_port         = 443
        protocol        = "tcp"
        security_groups = [aws_security_group.security_group_alb.id]
    }

    ingress {
        description     = "Trafic HTTPS from ALB"
        from_port       = 8080
        to_port         = 8080
        protocol        = "tcp"
        security_groups = [aws_security_group.security_group_alb.id]
    }

    egress {
        from_port        = 0
        to_port          = 0
        protocol         = "-1"
        cidr_blocks      = ["0.0.0.0/0"]
        ipv6_cidr_blocks = ["::/0"]
    }

    tags = merge(local.common_tags, {
        Name = local.is_ec2 ? "security_group_ec2" : "security_group_fargate"
    })

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

# ─── ALB ─────────────────────────────────────────────────────────────────────

resource "aws_lb" "load_balancer" {
    name                       = var.name_load_balancer
    internal                   = false
    load_balancer_type         = "application"
    security_groups            = [aws_security_group.security_group_alb.id]
    subnets                    = var.public_subnets
    enable_waf_fail_open       = false
    enable_deletion_protection = true

    access_logs {
        bucket  = local.bucket_id
        enabled = true
    }

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

resource "aws_lb_target_group" "target_group" {
    name        = "${var.name_load_balancer}-tg"
    port        = local.app_port
    protocol    = "HTTP"
    target_type = "ip"
    vpc_id      = var.vpc_id
    load_balancing_algorithm_type = var.load_balancing_algorithm_type

    health_check {
        path                = "/healthcheck"
        timeout             = var.hc_timeout
        healthy_threshold   = var.hc_healthy_threshold
        unhealthy_threshold = var.hc_unhealthy_threshold
    }

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

resource "aws_lb_listener" "listener_default_secure" {
    load_balancer_arn = aws_lb.load_balancer.arn
    port              = "443"
    protocol          = "HTTPS"
    ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
    certificate_arn   = var.certificate_arn

    default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.target_group.arn
    }

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

resource "aws_lb_listener" "listener_default" {
    load_balancer_arn = aws_lb.load_balancer.arn
    port              = "80"
    protocol          = "HTTP"

    default_action {
        type             = "redirect"
        target_group_arn = aws_lb_target_group.target_group.arn
        redirect {
            port        = "443"
            protocol    = "HTTPS"
            status_code = "HTTP_301"
        }
    }

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

resource "aws_wafv2_web_acl_association" "web_acl_association" {
    resource_arn = aws_lb.load_balancer.arn
    web_acl_arn  = var.web_acl_arn
}

# ─── Recursos EC2 (solo cuando launch_type = "EC2") ──────────────────────────

data "aws_ami" "ubuntu_ecs" {
    count       = local.is_ec2 ? 1 : 0
    most_recent = true
    owners      = ["amazon"]

    filter {
        name   = "name"
        values = ["amzn2-ami-ecs-hvm-*"]
    }
    filter {
        name   = "root-device-type"
        values = ["ebs"]
    }
    filter {
        name   = "virtualization-type"
        values = ["hvm"]
    }
    filter {
        name   = "state"
        values = ["available"]
    }
    filter {
        name   = "architecture"
        values = ["x86_64"]
    }
}

resource "aws_launch_template" "template" {
    count         = local.is_ec2 ? 1 : 0
    name          = "template${var.name_main}"
    image_id      = data.aws_ami.ubuntu_ecs[0].id
    instance_type = "t3.medium"
    key_name      = var.key_pair

    block_device_mappings {
        device_name = "/dev/sda1"
        ebs {
            volume_size = 20
            volume_type = "gp3"
        }
    }

    monitoring {
        enabled = true
    }

    metadata_options {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 2
    }

    network_interfaces {
        associate_public_ip_address = false
        security_groups             = [aws_security_group.security_group_ec2.id]
    }

    iam_instance_profile {
        name = var.role_ec2
    }

    tag_specifications {
        resource_type = "instance"
        tags = merge(local.common_tags, {
            Name = "Template${var.name_main}"
        })
    }

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }

    user_data = local.user_data_script != null ? base64encode(local.user_data_script) : null
}

resource "aws_autoscaling_group" "autoscaling_group" {
    count               = local.is_ec2 ? 1 : 0
    vpc_zone_identifier = var.private_subnets
    desired_capacity    = var.asg_desired_capacity
    max_size            = var.asg_max_size
    min_size            = var.asg_min_size
    force_delete        = true

    launch_template {
        id      = aws_launch_template.template[0].id
        version = "$Latest"
    }

    health_check_type         = "EC2"
    health_check_grace_period = 1000

    enabled_metrics = [
        "GroupMinSize",
        "GroupMaxSize",
        "GroupDesiredCapacity",
        "GroupInServiceInstances",
        "GroupPendingInstances",
        "GroupStandbyInstances",
        "GroupTerminatingInstances",
        "GroupTotalInstances",
    ]

    dynamic "tag" {
        for_each = merge(local.common_tags, var.ecs_connect ? { AmazonECSManaged = "true" } : {})
        content {
            key                 = tag.key
            value               = tag.value
            propagate_at_launch = true
        }
    }
}

resource "aws_autoscaling_policy" "scale_up" {
    count           = local.is_ec2 ? 1 : 0
    name            = "ec2-policy-scale-up-${var.name_main}"
    adjustment_type = "ChangeInCapacity"
    policy_type     = "StepScaling"

    step_adjustment {
        metric_interval_lower_bound = 0
        scaling_adjustment          = 1
    }

    autoscaling_group_name = aws_autoscaling_group.autoscaling_group[0].name
}

resource "aws_autoscaling_policy" "scale_down" {
    count           = local.is_ec2 ? 1 : 0
    name            = "ec2-policy-scale-down-${var.name_main}"
    adjustment_type = "ChangeInCapacity"
    policy_type     = "StepScaling"

    step_adjustment {
        metric_interval_lower_bound = 0
        scaling_adjustment          = -1
    }

    autoscaling_group_name = aws_autoscaling_group.autoscaling_group[0].name
}

# Alarmas por CPU
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
    count               = local.is_ec2 ? 1 : 0
    alarm_name          = "ec2-cpu-high-${var.name_main}"
    comparison_operator = "GreaterThanOrEqualToThreshold"
    evaluation_periods  = 2
    metric_name         = "CPUUtilization"
    namespace           = "AWS/EC2"
    period              = 60
    statistic           = "Average"
    unit                = "Percent"
    threshold           = 70

    dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.autoscaling_group[0].name
    }

    alarm_actions = [aws_autoscaling_policy.scale_up[0].arn]

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

resource "aws_cloudwatch_metric_alarm" "cpu_low" {
    count               = local.is_ec2 ? 1 : 0
    alarm_name          = "ec2-cpu-low-${var.name_main}"
    comparison_operator = "LessThanOrEqualToThreshold"
    evaluation_periods  = 2
    metric_name         = "CPUUtilization"
    namespace           = "AWS/EC2"
    period              = 240
    statistic           = "Average"
    unit                = "Percent"
    threshold           = 10

    dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.autoscaling_group[0].name
    }

    alarm_actions = [aws_autoscaling_policy.scale_down[0].arn]

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

# Alarmas por Memory
resource "aws_cloudwatch_metric_alarm" "memory_high" {
    count               = local.is_ec2 ? 1 : 0
    alarm_name          = "ec2-memory-high-${var.name_main}"
    comparison_operator = "GreaterThanOrEqualToThreshold"
    evaluation_periods  = 2
    metric_name         = "MemoryUtilization"
    namespace           = "AWS/EC2"
    period              = 60
    statistic           = "Average"
    unit                = "Percent"
    threshold           = 70

    dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.autoscaling_group[0].name
    }

    alarm_actions = [aws_autoscaling_policy.scale_up[0].arn]

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

resource "aws_cloudwatch_metric_alarm" "memory_low" {
    count               = local.is_ec2 ? 1 : 0
    alarm_name          = "ec2-memory-low-${var.name_main}"
    comparison_operator = "LessThanOrEqualToThreshold"
    evaluation_periods  = 2
    metric_name         = "MemoryUtilization"
    namespace           = "AWS/EC2"
    period              = 240
    statistic           = "Average"
    unit                = "Percent"
    threshold           = 10

    dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.autoscaling_group[0].name
    }

    alarm_actions = [aws_autoscaling_policy.scale_down[0].arn]

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

resource "aws_ecs_capacity_provider" "ecs_capacity_provider" {
    count = local.is_ec2 && var.ecs_connect ? 1 : 0
    name  = "capacity-provider-${var.name_main}"

    auto_scaling_group_provider {
        auto_scaling_group_arn         = aws_autoscaling_group.autoscaling_group[0].arn
        managed_termination_protection = "DISABLED"

        managed_scaling {
            instance_warmup_period    = 300
            maximum_scaling_step_size = 1000
            minimum_scaling_step_size = 1
            status                    = "ENABLED"
            target_capacity           = 100
        }
    }

    tags = local.common_tags

    lifecycle {
        ignore_changes = [tags["ORDEN"], tags["Name"]]
    }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
    count        = local.is_ec2 && var.ecs_connect ? 1 : 0
    cluster_name = var.name_cluster_ecs

    capacity_providers = [aws_ecs_capacity_provider.ecs_capacity_provider[0].name]

    default_capacity_provider_strategy {
        base              = 1
        weight            = 100
        capacity_provider = aws_ecs_capacity_provider.ecs_capacity_provider[0].name
    }
}
