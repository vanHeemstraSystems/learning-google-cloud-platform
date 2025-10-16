terraform {
required_version = “>= 1.5.0”

required_providers {
google = {
source  = “hashicorp/google”
version = “~> 5.0”
}
}
}

variable “project_id” {
description = “GCP Project ID”
type        = string
}

variable “region” {
description = “GCP Region”
type        = string
default     = “us-central1”
}

variable “alert_email” {
description = “Email for security alerts”
type        = string
default     = “security@example.com”
}

provider “google” {
project = var.project_id
region  = var.region
}

# Enable required APIs

resource “google_project_service” “required_apis” {
for_each = toset([
“cloudfunctions.googleapis.com”,
“cloudscheduler.googleapis.com”,
“pubsub.googleapis.com”,
“storage.googleapis.com”,
“logging.googleapis.com”,
“secretmanager.googleapis.com”,
“cloudresourcemanager.googleapis.com”,
“compute.googleapis.com”,
“iam.googleapis.com”,
])

service            = each.key
disable_on_destroy = false
}

# Storage bucket for security reports

resource “google_storage_bucket” “security_reports” {
name          = “${var.project_id}-security-reports”
location      = var.region
force_destroy = false

uniform_bucket_level_access = true

versioning {
enabled = true
}

lifecycle_rule {
condition {
age = 90
}
action {
type = “Delete”
}
}

encryption {
default_kms_key_name = google_kms_crypto_key.security_key.id
}

depends_on = [
google_project_service.required_apis,
google_kms_crypto_key_iam_member.storage_encryption
]
}

# Cloud KMS for encryption

resource “google_kms_key_ring” “security_keyring” {
name     = “security-keyring”
location = var.region

depends_on = [google_project_service.required_apis]
}

resource “google_kms_crypto_key” “security_key” {
name            = “security-reports-key”
key_ring        = google_kms_key_ring.security_keyring.id
rotation_period = “7776000s” # 90 days

lifecycle {
prevent_destroy = false
}
}

# IAM binding for Cloud Storage to use KMS key

resource “google_kms_crypto_key_iam_member” “storage_encryption” {
crypto_key_id = google_kms_crypto_key.security_key.id
role          = “roles/cloudkms.cryptoKeyEncrypterDecrypter”
member        = “serviceAccount:service-${data.google_project.project.number}@gs-project-accounts.iam.gserviceaccount.com”
}

# Get project number

data “google_project” “project” {
project_id = var.project_id
}

# Pub/Sub topic for security scan trigger

resource “google_pubsub_topic” “security_scan” {
name = “security-scan”

depends_on = [google_project_service.required_apis]
}

# Pub/Sub topic for security alerts

resource “google_pubsub_topic” “security_alerts” {
name = “security-alerts”

depends_on = [google_project_service.required_apis]
}

# Pub/Sub subscription for alerts

resource “google_pubsub_subscription” “security_alerts_sub” {
name  = “security-alerts-subscription”
topic = google_pubsub_topic.security_alerts.name

ack_deadline_seconds = 20

expiration_policy {
ttl = “” # Never expire
}

retry_policy {
minimum_backoff = “10s”
maximum_backoff = “600s”
}
}

# Service account for Cloud Functions

resource “google_service_account” “function_sa” {
account_id   = “security-scanner-sa”
display_name = “Security Scanner Service Account”
description  = “Service account for security scanning functions”
}

# IAM roles for service account

resource “google_project_iam_member” “function_sa_roles” {
for_each = toset([
“roles/storage.admin”,
“roles/logging.logWriter”,
“roles/pubsub.publisher”,
“roles/iam.securityReviewer”,
“roles/compute.viewer”,
])

project = var.project_id
role    = each.key
member  = “serviceAccount:${google_service_account.function_sa.email}”
}

# Cloud Scheduler job to trigger security scan

resource “google_cloud_scheduler_job” “security_scan_job” {
name             = “security-scan-job”
description      = “Triggers security scan daily”
schedule         = “0 2 * * *” # Run at 2 AM UTC daily
time_zone        = “UTC”
attempt_deadline = “320s”

pubsub_target {
topic_name = google_pubsub_topic.security_scan.id
data       = base64encode(jsonencode({
project_id = var.project_id
}))
}

depends_on = [google_project_service.required_apis]
}

# Cloud Storage bucket for function source code

resource “google_storage_bucket” “function_source” {
name          = “${var.project_id}-function-source”
location      = var.region
force_destroy = true

uniform_bucket_level_access = true

depends_on = [google_project_service.required_apis]
}

# Outputs

output “security_reports_bucket” {
value       = google_storage_bucket.security_reports.name
description = “Name of the bucket storing security reports”
}

output “security_scan_topic” {
value       = google_pubsub_topic.security_scan.name
description = “Pub/Sub topic for triggering scans”
}

output “security_alerts_topic” {
value       = google_pubsub_topic.security_alerts.name
description = “Pub/Sub topic for security alerts”
}

output “service_account_email” {
value       = google_service_account.function_sa.email
description = “Service account email for the function”
}

output “scheduler_job_name” {
value       = google_cloud_scheduler_job.security_scan_job.name
description = “Cloud Scheduler job name”
}
