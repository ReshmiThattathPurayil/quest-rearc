resource "aws_ecr_repository" "test_reshmi" {
  name                 = "test-reshmi"
  image_tag_mutability = "IMMUTABLE"

  tags = merge(
    local.tags,
    {
      tier        = "app"
      customer    = "reshmi"
      environment = "poc"
    }
  )
}
