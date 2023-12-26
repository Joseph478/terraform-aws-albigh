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
    description = "EC2 Role"
    type = string
}
variable "name_cluster_ecs" {
    description = "Name of the cluster"
    type = string
}