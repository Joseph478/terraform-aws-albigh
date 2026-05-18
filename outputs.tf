output "arn_alb"{
    value = aws_lb.load_balancer.arn
}
output "name_alb"{
    value = aws_lb.load_balancer.name
}
output "security_groups_alb"{
    value = aws_lb.load_balancer.security_groups
}
output "dns_alb"{
    value = aws_lb.load_balancer.dns_name
}
output "web_acl_arn"{
    value = var.web_acl_arn
}
output "arn_target_group" {
    value = aws_lb_target_group.target_group.arn
}
output "id_security_group_ec2" {
    value = aws_security_group.security_group_ec2.id
}

output "id_security_group_alb" {
    value = aws_security_group.security_group_alb.id
}

output "zone_id_alb" {
    value = aws_lb.load_balancer.zone_id
}

output "name_target_group" {
    value = aws_lb_target_group.target_group.name
}

output "arn_listener_https" {
    value = aws_lb_listener.listener_default_secure.arn
}

output "arn_listener_http" {
    value = aws_lb_listener.listener_default.arn
}

output "id_s3_bucket" {
    value = try(aws_s3_bucket.bucket[0].id, null)
}

output "arn_s3_bucket" {
    value = try(aws_s3_bucket.bucket[0].arn, null)
}

output "id_launch_template" {
    value = try(aws_launch_template.template[0].id, null)
}

output "name_autoscaling_group" {
    value = try(aws_autoscaling_group.autoscaling_group[0].name, null)
}

output "arn_autoscaling_group" {
    value = try(aws_autoscaling_group.autoscaling_group[0].arn, null)
}

output "name_ecs_capacity_provider" {
    value = try(aws_ecs_capacity_provider.ecs_capacity_provider[0].name, null)
}