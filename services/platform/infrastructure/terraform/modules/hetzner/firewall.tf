# Hetzner Cloud Firewall Configuration
# Secures the hosting node with appropriate port access

resource "hcloud_firewall" "node" {
  name = "${var.hostname}-fw"

  labels = {
    managed_by   = "praho"
    deployment   = var.deployment_id
    environment  = var.environment
    node_type    = var.node_type
  }

  # SSH - Open to all (or restricted via variable)
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.firewall_ssh_sources
    description = "SSH access"
  }

  # Webmin/Virtualmin HTTPS (port 10000)
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "10000"
    source_ips = var.firewall_webmin_sources
    description = "Webmin/Virtualmin HTTPS"
  }

  # HTTP - Web hosting
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "HTTP"
  }

  # HTTPS - Web hosting
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "HTTPS"
  }

  # SMTP - Email sending
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "25"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "SMTP"
  }

  # SMTPS - Secure email submission
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "465"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "SMTPS"
  }

  # Submission - Email submission
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "587"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "Email submission"
  }

  # IMAPS - Secure IMAP
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "993"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "IMAPS"
  }

  # POP3S - Secure POP3
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "995"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "POP3S"
  }

  # FTP - File transfer
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "21"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "FTP control"
  }

  # FTP Passive Mode - Data transfer
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "40000-40100"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "FTP passive mode"
  }

  # DNS UDP - If server acts as DNS
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "53"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "DNS UDP"
  }

  # DNS TCP - If server acts as DNS
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "53"
    source_ips = ["0.0.0.0/0", "::/0"]
    description = "DNS TCP"
  }

  # MySQL - For remote database access (optional, usually localhost only)
  # Uncomment if needed for specific use cases
  # rule {
  #   direction  = "in"
  #   protocol   = "tcp"
  #   port       = "3306"
  #   source_ips = ["0.0.0.0/0", "::/0"]
  #   description = "MySQL"
  # }

  # Allow all outbound traffic
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "All outbound TCP"
  }

  rule {
    direction       = "out"
    protocol        = "udp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "All outbound UDP"
  }

  rule {
    direction       = "out"
    protocol        = "icmp"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "ICMP outbound"
  }
}
