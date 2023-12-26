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