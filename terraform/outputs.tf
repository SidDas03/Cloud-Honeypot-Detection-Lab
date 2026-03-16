# outputs.tf — Values displayed after terraform apply

output "honeypot_public_ip" {
  description = "Public IP address of the honeypot instance"
  value       = aws_eip.honeypot_eip.public_ip
}

output "honeypot_instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.honeypot.id
}

output "honeypot_public_dns" {
  description = "Public DNS name of the honeypot"
  value       = aws_instance.honeypot.public_dns
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.honeypot_detector.id
}

output "cloudtrail_bucket" {
  description = "S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_bucket.bucket
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = aws_sns_topic.honeypot_alerts.arn
}

output "ssh_command" {
  description = "SSH command to connect to the honeypot (admin use only)"
  value       = "ssh -i your-key.pem ubuntu@${aws_eip.honeypot_eip.public_ip}"
}

output "cowrie_log_path" {
  description = "Path to Cowrie logs on the honeypot instance"
  value       = "/home/cowrie/var/log/cowrie/cowrie.json"
}
