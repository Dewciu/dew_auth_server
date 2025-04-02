variable "aws_region" {
  description = "The AWS region to create resources in"
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name, e.g. 'prod', 'staging', 'dev'"
  default     = "dev"
}

variable "db_username" {
  description = "Username for the RDS PostgreSQL instance"
  default     = "dew_auth"
}

variable "db_password" {
  description = "Password for the RDS PostgreSQL instance"
  sensitive   = true
}

variable "session_signing_key" {
  description = "Key used for signing sessions"
  sensitive   = true
}

variable "session_encryption_key" {
  description = "Key used for encrypting sessions"
  sensitive   = true
}

variable "container_image" {
  description = "Docker image for the Dew Auth Server"
  default     = "yourdockerhubusername/dew-auth-server:latest"
}

variable "service_desired_count" {
  description = "Number of tasks to run in the service"
  default     = 2
}

variable "domain_name" {
  description = "Domain name for the application"
  default     = "auth.example.com"
}

variable "route53_zone_id" {
  description = "Zone ID for the Route53 zone"
  default     = ""
}