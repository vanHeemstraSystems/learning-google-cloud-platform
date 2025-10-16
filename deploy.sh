#!/bin/bash

# GCP Security Scanner - Deployment Script

# This script deploys the complete security scanning infrastructure

set -e

# Color codes for output

RED=’\033[0;31m’
GREEN=’\033[0;32m’
YELLOW=’\033[1;33m’
NC=’\033[0m’ # No Color

echo -e “${GREEN}=====================================${NC}”
echo -e “${GREEN}GCP Security Scanner Deployment${NC}”
echo -e “${GREEN}=====================================${NC}”
echo “”

# Check prerequisites

echo -e “${YELLOW}Checking prerequisites…${NC}”

if ! command -v gcloud &> /dev/null; then
echo -e “${RED}Error: gcloud CLI not found. Please install Google Cloud SDK.${NC}”
exit 1
fi

if ! command -v terraform &> /dev/null; then
echo -e “${RED}Error: terraform not found. Please install Terraform.${NC}”
exit 1
fi

echo -e “${GREEN}✓ Prerequisites met${NC}”
echo “”

# Get configuration

read -p “Enter your GCP Project ID: “ PROJECT_ID
read -p “Enter region (default: us-central1): “ REGION
REGION=${REGION:-us-central1}
read -p “Enter alert email (default: security@example.com): “ ALERT_EMAIL
ALERT_EMAIL=${ALERT_EMAIL:-security@example.com}

echo “”
echo -e “${YELLOW}Configuration:${NC}”
echo “  Project ID: $PROJECT_ID”
echo “  Region: $REGION”
echo “  Alert Email: $ALERT_EMAIL”
echo “”

read -p “Continue with deployment? (y/n) “ -n 1 -r
echo “”
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
echo “Deployment cancelled.”
exit 1
fi

# Set gcloud project

echo -e “${YELLOW}Setting active project…${NC}”
gcloud config set project $PROJECT_ID

# Enable required APIs

echo -e “${YELLOW}Enabling required APIs…${NC}”
gcloud services enable   
cloudfunctions.googleapis.com   
cloudscheduler.googleapis.com   
pubsub.googleapis.com   
storage.googleapis.com   
logging.googleapis.com   
cloudresourcemanager.googleapis.com   
compute.googleapis.com   
iam.googleapis.com   
cloudbuild.googleapis.com

echo -e “${GREEN}✓ APIs enabled${NC}”
echo “”

# Deploy infrastructure with Terraform

echo -e “${YELLOW}Deploying infrastructure with Terraform…${NC}”
cd terraform

terraform init

terraform plan   
-var=“project_id=$PROJECT_ID”   
-var=“region=$REGION”   
-var=“alert_email=$ALERT_EMAIL”

terraform apply   
-var=“project_id=$PROJECT_ID”   
-var=“region=$REGION”   
-var=“alert_email=$ALERT_EMAIL”   
-auto-approve

echo -e “${GREEN}✓ Infrastructure deployed${NC}”
echo “”

# Get outputs from Terraform

REPORTS_BUCKET=$(terraform output -raw security_reports_bucket)
SCAN_TOPIC=$(terraform output -raw security_scan_topic)
ALERTS_TOPIC=$(terraform output -raw security_alerts_topic)
SERVICE_ACCOUNT=$(terraform output -raw service_account_email)

cd ..

# Deploy Cloud Functions

echo -e “${YELLOW}Deploying Cloud Functions…${NC}”

# Deploy security scanner function

echo “  Deploying security scanner…”
cd functions/scanner
gcloud functions deploy security-scanner   
–gen2   
–runtime python311   
–region $REGION   
–source .   
–entry-point scan_resources   
–trigger-topic $SCAN_TOPIC   
–service-account $SERVICE_ACCOUNT   
–memory 512MB   
–timeout 540s   
–set-env-vars PROJECT_ID=$PROJECT_ID

cd ../..
echo -e “${GREEN}✓ Security scanner deployed${NC}”

# Deploy alert handler function

echo “  Deploying alert handler…”
cd functions/alerts
gcloud functions deploy alert-handler   
–gen2   
–runtime python311   
–region $REGION   
–source .   
–entry-point handle_alert   
–trigger-topic $ALERTS_TOPIC   
–service-account $SERVICE_ACCOUNT   
–memory 256MB   
–timeout 60s   
–set-env-vars PROJECT_ID=$PROJECT_ID,ALERT_EMAIL=$ALERT_EMAIL

cd ../..
echo -e “${GREEN}✓ Alert handler deployed${NC}”
echo “”

# Test the deployment

echo -e “${YELLOW}Testing deployment…${NC}”
echo “  Triggering manual security scan…”

gcloud pubsub topics publish $SCAN_TOPIC   
–message “{"project_id": "$PROJECT_ID"}”

echo -e “${GREEN}✓ Test scan triggered${NC}”
echo “”

# Display summary

echo -e “${GREEN}=====================================${NC}”
echo -e “${GREEN}Deployment Complete!${NC}”
echo -e “${GREEN}=====================================${NC}”
echo “”
echo -e “${YELLOW}Resources Created:${NC}”
echo “  • Security Reports Bucket: gs://$REPORTS_BUCKET”
echo “  • Scanner Function: security-scanner”
echo “  • Alert Handler Function: alert-handler”
echo “  • Pub/Sub Topic (Scan): $SCAN_TOPIC”
echo “  • Pub/Sub Topic (Alerts): $ALERTS_TOPIC”
echo “  • Service Account: $SERVICE_ACCOUNT”
echo “  • Cloud Scheduler: security-scan-job (runs daily at 2 AM UTC)”
echo “”

echo -e “${YELLOW}Next Steps:${NC}”
echo “  1. Check logs:”
echo “     gcloud logging read "resource.type=cloud_function" –limit 20”
echo “”
echo “  2. View reports:”
echo “     gsutil ls gs://$REPORTS_BUCKET/”
echo “”
echo “  3. Trigger manual scan:”
echo “     gcloud scheduler jobs run security-scan-job –location=$REGION”
echo “”
echo “  4. Monitor alerts:”
echo “     gcloud logging read "jsonPayload.alert_type=security_finding" –limit 10”
echo “”

echo -e “${YELLOW}Useful Commands:${NC}”
echo “  • View function logs:”
echo “    gcloud functions logs read security-scanner –region $REGION –limit 50”
echo “”
echo “  • Test alert handler:”
echo “    gcloud functions call alert-handler –region $REGION –data ‘{"findings":[]}’
“
echo “”

echo -e “${GREEN}Deployment successful! Security scanning is now active.${NC}”
