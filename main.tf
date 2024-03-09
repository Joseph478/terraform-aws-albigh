

resource "aws_s3_bucket" "bucket" {
  bucket = "bucket${var.name_main}"

  tags = {
    Name        = "Bucket${var.name_main}terraform"
    ENV = "PROD"
    SERVICE = upper(var.name_main)
  }
}
resource "aws_s3_bucket_ownership_controls" "ownership_controls" {
  bucket = aws_s3_bucket.bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "s3_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.ownership_controls]

  bucket = aws_s3_bucket.bucket.id
  acl    = "private"
}

resource "aws_security_group" "security_group_alb" {
  name        = "sg_alb_${var.name_main}_security_group"
  description = "Allow inbound traffic"
  vpc_id      = var.vpc_id

  # ingress {
  #   description      = "Trafic HTTP from VPC"
  #   from_port        = 80
  #   to_port          = 80
  #   protocol         = "tcp"
  #   cidr_blocks      = ["0.0.0.0/0"]
  #   # ipv6_cidr_blocks = ["::/0"]
  # }
  ingress {
    description      = "Trafic HTTPS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    # ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "security_group_alb"
  }
}

resource "aws_lb" "load_balancer" {
    name               = var.name_load_balancer
    
    internal           = false
    load_balancer_type = "application"
    security_groups    = [aws_security_group.security_group_alb.id]
    subnets            = var.subnets
    enable_waf_fail_open  = false
    enable_deletion_protection = false

    # access_logs {
    #     bucket  = aws_s3_bucket.bucket.id
    #     prefix  = "lb-logs"
    #     enabled = true
    # }

    tags = {
        ENV = "PROD"
        SERVICE     = "MMG"
    }
}


# Permisos para ELB  
data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket_policy" "logs_policy" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.logs_document.json
}

data "aws_iam_policy_document" "logs_document" {
  statement {
    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${aws_s3_bucket.bucket.id}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.main.id]
    }
  }
}

resource "aws_lb_target_group" "target_group" {
    name     = "${var.name_load_balancer}-tg"
    port     = 80
    protocol = "HTTP"
    target_type = "ip"
    vpc_id   = var.vpc_id
    
    health_check {
      path = "/healthcheck"
      healthy_threshold = 2
    }
}
resource "aws_lb_listener" "listener_default_secure" {
    load_balancer_arn = aws_lb.load_balancer.arn
    port              = "443"
    protocol          = "HTTPS"
    ssl_policy        = "ELBSecurityPolicy-2016-08"
    certificate_arn   = var.certificate_arn

    default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.target_group.arn
    }
}
resource "aws_lb_listener" "listener_default" {
  load_balancer_arn = aws_lb.load_balancer.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    target_group_arn = aws_lb_target_group.target_group.arn
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}


resource "aws_wafv2_web_acl_association" "web_acl_association" {

  resource_arn = aws_lb.load_balancer.arn
  web_acl_arn  = var.web_acl_arn
}

locals {
  ami_filters = {
    name = "amzn2-ami-ecs-hvm-*"
    root-device-type = "ebs"
    virtualization-type = "hvm"
    state = "available"
    architecture = "x86_64"
  }
}

data "aws_ami" "ubuntu_ecs" {
  most_recent = true
  owners = ["amazon"]

  dynamic "filter" {
    for_each = local.ami_filters
    content {
      name = filter.key
      values = [filter.value]
    }
  }
}

resource "aws_security_group" "security_group_ec2" {
  name        = "sg_instance_${var.name_main}"
  description = "Allow inbound traffic"
  vpc_id      = var.vpc_id

  # ingress {
  #   description      = "All Trafic"
  #   from_port        = 0
  #   to_port          = 0
  #   protocol         = "-1"
  #   # cidr_blocks      =  ["192.168.0.0/16"]
  #   security_groups = [aws_security_group.security_group_alb.id]
  # }
  ingress {
    description      = "Trafic HTTP from VPC"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    security_groups = [aws_security_group.security_group_alb.id]
    # cidr_blocks      = ["0.0.0.0/0"]
    # ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    description      = "Trafic HTTPS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    security_groups = [aws_security_group.security_group_alb.id]
    # cidr_blocks      = ["0.0.0.0/0"]
    # ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "security_group_ec2"
  }
}

resource "aws_launch_template" "template" {
  # Name of the launch template
  name          = "template${var.name_main}"

  # ID of the Amazon Machine Image (AMI) to use for the instance
  image_id      = data.aws_ami.ubuntu_ecs.id
  # image_id      = "ami-00eb0dc604a8124fd"

  # Instance type for the EC2 instance
  instance_type = "t3.medium"

  # SSH key pair name for connecting to the instance
  key_name = var.key_pair

  # Block device mappings for the instance
  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      # Size of the EBS volume in GB
      volume_size = 20

      # Type of EBS volume (General Purpose SSD in this case)
      volume_type = "gp3"
    }
  }
  # instance_market_options {
  #   market_type = "spot"
  # }
  monitoring {
    enabled = true
  }
  # Network interface configuration
  network_interfaces {
    # Associates a public IP address with the instance
    associate_public_ip_address = true
    
    # Security groups to associate with the instance
    security_groups = [aws_security_group.security_group_ec2.id]
  }
  iam_instance_profile {

    name = var.role_ec2
  }
  # Tag specifications for the instance
  tag_specifications {
    # Specifies the resource type as "instance"
    resource_type = "instance"

    # Tags to apply to the instance
    tags = {
      Name = "Template${var.name_main}"
    }
  }
  user_data = base64encode(<<-EOF
                  #!/bin/bash
                  echo ECS_CLUSTER=${var.name_cluster_ecs} >> /etc/ecs/ecs.config
                  echo ECS_BACKEND_HOST= >> /etc/ecs/ecs.config
                EOF
                )
}

resource "aws_autoscaling_group" "autoscaling_group" {
  vpc_zone_identifier           = var.subnets
  desired_capacity              = 2
  max_size                      = 4
  min_size                      = 2
  force_delete                  = true
  launch_template {
    id                          = aws_launch_template.template.id
    version                     = "$Latest"
  }
  health_check_type             = "EC2"
  health_check_grace_period     = 1000
  enabled_metrics               = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]
  tag {
    key                         = "AmazonECSManaged"
    value                       = true
    propagate_at_launch         = true
  }
}

resource "aws_autoscaling_policy" "scale_up" {
  name = "ec2-policy-scale-up-${var.name_main}"
  # scaling_adjustment = "1"
  step_adjustment {
    metric_interval_lower_bound = 0
    # metric_interval_upper_bound = 100
    scaling_adjustment = "1"
  }
  adjustment_type = "ChangeInCapacity"
  policy_type = "StepScaling"
  # cooldown = "60"
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
}
resource "aws_autoscaling_policy" "scale_down" {
  name = "ec2-policy-scale-down-${var.name_main}"
  # scaling_adjustment = "-1" 
  step_adjustment {
    metric_interval_lower_bound = 0
    # metric_interval_upper_bound = 100
    scaling_adjustment = "-1"
  }
  adjustment_type = "ChangeInCapacity"
  policy_type = "StepScaling"
  # cooldown = "60"
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
}

# Alarmas por CPU 
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
    alarm_name = "ec2-cpu-high-${var.name_main}"
    comparison_operator = "GreaterThanOrEqualToThreshold"
    evaluation_periods = 2
    metric_name = "CPUUtilization" 
    namespace = "AWS/EC2"
    period = 60
    statistic = "Average"
    unit = "Percent"
    threshold = 70

    dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.autoscaling_group.name
    }

    alarm_actions = [aws_autoscaling_policy.scale_up.arn]
}
resource "aws_cloudwatch_metric_alarm" "cpu_low" {
    alarm_name = "ec2-cpu-low-${var.name_main}"
    comparison_operator = "LessThanOrEqualToThreshold"
    evaluation_periods = 2
    metric_name = "CPUUtilization" 
    namespace = "AWS/EC2"
    period = 240
    statistic = "Average"
    unit = "Percent"
    threshold = 10

    dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.autoscaling_group.name
    }

    alarm_actions = [aws_autoscaling_policy.scale_down.arn]
}

# Alarmas por MEMORY 
resource "aws_cloudwatch_metric_alarm" "memory_high" {
    alarm_name = "ec2-memory-high-${var.name_main}"
    comparison_operator = "GreaterThanOrEqualToThreshold"
    evaluation_periods = 2
    metric_name = "MemoryUtilization" 
    namespace = "AWS/EC2"
    period = 60
    statistic = "Average"
    unit = "Percent"
    threshold = 70

    dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.autoscaling_group.name
    }

    alarm_actions = [aws_autoscaling_policy.scale_up.arn]
}
resource "aws_cloudwatch_metric_alarm" "memory_low" {
    alarm_name = "ec2-memory-low-${var.name_main}"
    comparison_operator = "LessThanOrEqualToThreshold"
    evaluation_periods = 2
    metric_name = "MemoryUtilization" 
    namespace = "AWS/EC2"
    period = 240
    statistic = "Average"
    unit = "Percent"
    threshold = 10 

    dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.autoscaling_group.name
    }

    alarm_actions = [aws_autoscaling_policy.scale_down.arn]
}

# resource "aws_autoscaling_attachment" "asg_attachment" {
#   autoscaling_group_name = aws_autoscaling_group.autoscaling_group.id
#   lb_target_group_arn    = aws_lb_target_group.target_group.arn
# }
resource "aws_ecs_capacity_provider" "ecs_capacity_provider" {
  name = "capacity-provider-${var.name_main}"

  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.autoscaling_group.arn
    managed_termination_protection = "DISABLED"

    managed_scaling {
      instance_warmup_period = 300
      maximum_scaling_step_size = 1000
      minimum_scaling_step_size = 1
      status                    = "ENABLED"
      target_capacity           = 10
    }
  }
}