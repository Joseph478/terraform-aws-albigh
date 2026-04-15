variable "web_acl_arn" {
    description = "Web acl arn"
    type        = string
}
variable "certificate_arn" {
    description = "Certificate arn"
    type        = string
}
variable "name_load_balancer" {
    default = "load_balancer_default"
    description = "Name of the load balancer"
    type        = string
}
variable "account_id" {
    description = "Account id"
    type = string
}
variable "vpc_id" {
    description = "VPC id"
    type = string
}
variable "subnets" {
    description = "Subnets of VPC"
    type = list(string)
}
variable "private_subnets" {
    description = "Private Subnets of VPC"
    type = list(string)
}
variable "name_main" {
    description = "Name main"
    type        = string
}
variable "key_pair" {
    default = "default_key"
    description = "Key pair of EC2"
    type = string
}
variable "role_ec2" {
    default     = "ROLE_PRIMARY"
    description = "EC2 instance profile role. Only used when launch_type = 'EC2'"
    type        = string
}
variable "name_cluster_ecs" {
    description = "Name of the cluster"
    type        = string
}
variable "launch_type" {
    default     = "EC2"
    description = "ECS launch type. Allowed values: 'EC2', 'FARGATE'"
    type        = string

    validation {
        condition     = contains(["EC2", "FARGATE"], var.launch_type)
        error_message = "launch_type must be 'EC2' or 'FARGATE'."
    }
}

variable "asg_desired_capacity" {
    default     = 2
    description = "Desired number of EC2 instances in the Auto Scaling Group. Only used when launch_type = 'EC2'"
    type        = number
}

variable "asg_min_size" {
    default     = 2
    description = "Minimum number of EC2 instances in the Auto Scaling Group. Only used when launch_type = 'EC2'"
    type        = number
}

variable "asg_max_size" {
    default     = 4
    description = "Maximum number of EC2 instances in the Auto Scaling Group. Only used when launch_type = 'EC2'"
    type        = number
}

variable "load_balancing_algorithm_type" {
    default     = "least_outstanding_requests"
    description = "Load balancing algorithm for the target group. Allowed values: 'round_robin', 'least_outstanding_requests', 'weighted_random'"
    type        = string

    validation {
        condition     = contains(["round_robin", "least_outstanding_requests", "weighted_random"], var.load_balancing_algorithm_type)
        error_message = "load_balancing_algorithm_type must be 'round_robin', 'least_outstanding_requests', or 'weighted_random'."
    }
}

variable "type_project" {
    default     = "laravel"
    description = "Project type. Defines container port and target group port. Allowed values: 'laravel' (port 80), 'django' (port 8000)"
    type        = string

    validation {
        condition     = contains(["laravel", "django"], var.type_project)
        error_message = "type_project must be 'laravel' or 'django'."
    }
}