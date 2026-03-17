# AWS Module — EKS + KMS for MPC Wallet

variable "environment" { type = string }
variable "cluster_name" { type = string }
variable "node_count" { type = number }
variable "instance_type" { type = string }
variable "region" { type = string }

# ── KMS Key for key share envelope encryption ────────────────────────
resource "aws_kms_key" "mpc_key" {
  description             = "MPC Wallet key share encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${var.cluster_name}-kms"
  }
}

resource "aws_kms_alias" "mpc_key" {
  name          = "alias/${var.cluster_name}"
  target_key_id = aws_kms_key.mpc_key.key_id
}

# ── EKS Cluster ──────────────────────────────────────────────────────
resource "aws_eks_cluster" "mpc" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = var.environment != "production"
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.mpc_key.arn
    }
    resources = ["secrets"]
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}

# ── EKS Node Group ──────────────────────────────────────────────────
resource "aws_eks_node_group" "mpc_nodes" {
  cluster_name    = aws_eks_cluster.mpc.name
  node_group_name = "${var.cluster_name}-nodes"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = aws_subnet.private[*].id
  instance_types  = [var.instance_type]

  scaling_config {
    desired_size = var.node_count
    max_size     = var.node_count + 2
    min_size     = var.node_count
  }

  depends_on = [aws_iam_role_policy_attachment.eks_node]
}

# ── VPC (simplified) ────────────────────────────────────────────────
resource "aws_vpc" "mpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.cluster_name}-vpc" }
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.mpc.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = "${var.region}${["a", "b", "c"][count.index]}"

  tags = { Name = "${var.cluster_name}-private-${count.index}" }
}

# ── IAM Roles (minimal) ─────────────────────────────────────────────
resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role" "eks_node" {
  name = "${var.cluster_name}-eks-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_node" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node.name
}

# ── Outputs ──────────────────────────────────────────────────────────
output "cluster_endpoint" {
  value = aws_eks_cluster.mpc.endpoint
}

output "kms_key_arn" {
  value = aws_kms_key.mpc_key.arn
}
