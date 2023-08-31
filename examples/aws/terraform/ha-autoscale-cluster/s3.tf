// S3 bucket is used to distribute Let's Encrypt certificates
// For demo purposes, don't need bucket logging
// tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "certs" {
  bucket        = var.s3_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_acl" "certs" {
  depends_on = [aws_s3_bucket_ownership_controls.certs]
  bucket     = aws_s3_bucket.certs.bucket
  acl        = "private"
}

// For demo purposes, CMK is not needed
// tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "certs" {
  bucket = aws_s3_bucket.certs.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "certs" {
  bucket = aws_s3_bucket.certs.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_versioning" "certs" {
  bucket = aws_s3_bucket.certs.bucket

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "certs" {
  bucket = aws_s3_bucket.certs.bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "grafana_teleport_dashboard" {
  bucket = aws_s3_bucket.certs.bucket
  key    = "health-dashboard.json"
  source = "./assets/health-dashboard.json"
  etag   = filemd5("./assets/health-dashboard.json")
}

// Grafana nginx config (Let's Encrypt)
resource "aws_s3_object" "grafana_teleport_nginx" {
  bucket = aws_s3_bucket.certs.bucket
  key    = "grafana-nginx.conf"
  source = "./assets/grafana-nginx.conf"
  count  = var.use_acm ? 0 : 1
  etag   = filemd5("./assets/grafana-nginx.conf")
}

// Grafana nginx config (ACM)
resource "aws_s3_object" "grafana_teleport_nginx_acm" {
  bucket = aws_s3_bucket.certs.bucket
  key    = "grafana-nginx.conf"
  source = "./assets/grafana-nginx-acm.conf"
  count  = var.use_acm ? 1 : 0
  etag   = filemd5("./assets/grafana-nginx-acm.conf")
}
