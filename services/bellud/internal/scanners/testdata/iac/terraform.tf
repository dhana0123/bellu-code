resource "aws_s3_bucket" "public" {
  bucket = "bellu-fixture-public"
  acl    = "public-read"
}
