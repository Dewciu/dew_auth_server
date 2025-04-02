#!/bin/bash
# AWS deployment script for Dew Auth Server

set -e

# Default values
ENVIRONMENT="dev"
APPLY=false
DESTROY=false
AUTO_APPROVE=false
PLAN_ONLY=false
INIT=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --env)
      ENVIRONMENT="$2"
      shift 2
      ;;
    --apply)
      APPLY=true
      shift
      ;;
    --destroy)
      DESTROY=true
      shift
      ;;
    --auto-approve)
      AUTO_APPROVE=true
      shift
      ;;
    --plan-only)
      PLAN_ONLY=true
      shift
      ;;
    --no-init)
      INIT=false
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo "Deploy Dew Auth Server to AWS using Terraform."
      echo ""
      echo "Options:"
      echo "  --env ENV               Environment to deploy to (default: dev)"
      echo "  --apply                 Apply the Terraform plan"
      echo "  --destroy               Destroy the environment"
      echo "  --auto-approve          Auto-approve Terraform actions"
      echo "  --plan-only             Only create a plan, don't apply"
      echo "  --no-init               Skip Terraform initialization"
      echo "  --help, -h              Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Ensure AWS credentials are available
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
  echo "AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
  exit 1
fi

# Navigate to the Terraform directory
cd terraform/aws

# Create or update terraform.tfvars if it doesn't exist
if [ ! -f "terraform.tfvars" ]; then
  echo "Creating terraform.tfvars file..."
  
  cat > terraform.tfvars << EOF
environment = "${ENVIRONMENT}"
aws_region = "${AWS_REGION:-us-west-2}"
container_image = "${CONTAINER_IMAGE:-yourdockerhubusername/dew-auth-server:latest}"
db_username = "${DB_USERNAME:-dew_auth}"
db_password = "${DB_PASSWORD:-$(openssl rand -base64 12)}"
session_signing_key = "${SESSION_SIGNING_KEY:-$(openssl rand -hex 32)}"
session_encryption_key = "${SESSION_ENCRYPTION_KEY:-$(openssl rand -hex 32)}"
EOF

  echo "Generated terraform.tfvars with default values. Please review and update as needed."
  
  # If we just created the file with sensitive information, don't proceed automatically
  if [ "$AUTO_APPROVE" != "true" ]; then
    echo "Please review the terraform.tfvars file and run this script again with --apply."
    exit 0
  fi
fi

# Initialize Terraform if needed
if [ "$INIT" = true ]; then
  echo "Initializing Terraform..."
  terraform init
fi

# Handle destroy action
if [ "$DESTROY" = true ]; then
  echo "Planning infrastructure destruction for environment: $ENVIRONMENT"
  
  if [ "$AUTO_APPROVE" = true ]; then
    terraform destroy -auto-approve -var-file=terraform.tfvars
  else
    terraform destroy -var-file=terraform.tfvars
  fi
  
  echo "Infrastructure destruction completed."
  exit 0
fi

# Create Terraform plan
echo "Planning infrastructure for environment: $ENVIRONMENT"
terraform plan -var-file=terraform.tfvars -out=tfplan

# Exit if only planning
if [ "$PLAN_ONLY" = true ]; then
  echo "Plan created. Run with --apply to deploy infrastructure."
  exit 0
fi

# Apply Terraform plan if requested
if [ "$APPLY" = true ]; then
  echo "Applying infrastructure plan for environment: $ENVIRONMENT"
  
  if [ "$AUTO_APPROVE" = true ]; then
    terraform apply -auto-approve tfplan
  else
    terraform apply tfplan
  fi
  
  # Display outputs
  echo "Infrastructure deployment completed. Outputs:"
  terraform output
  
  # Save outputs to a file
  terraform output -json > "../../deploy-${ENVIRONMENT}-outputs.json"
  echo "Outputs saved to deploy-${ENVIRONMENT}-outputs.json"
else
  echo "Plan created but not applied. Run with --apply to deploy infrastructure."
fi

echo "Deployment script completed."