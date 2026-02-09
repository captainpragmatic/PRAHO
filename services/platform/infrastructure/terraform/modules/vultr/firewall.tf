# Vultr Firewall Configuration
# Secures the hosting node with appropriate port access

# SSH Access
resource "vultr_firewall_rule" "ssh" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "22"
  notes             = "SSH access"
}

resource "vultr_firewall_rule" "ssh_v6" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
  port              = "22"
  notes             = "SSH access IPv6"
}

# HTTP
resource "vultr_firewall_rule" "http" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "80"
  notes             = "HTTP"
}

resource "vultr_firewall_rule" "http_v6" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
  port              = "80"
  notes             = "HTTP IPv6"
}

# HTTPS
resource "vultr_firewall_rule" "https" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "443"
  notes             = "HTTPS"
}

resource "vultr_firewall_rule" "https_v6" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
  port              = "443"
  notes             = "HTTPS IPv6"
}

# Webmin/Virtualmin (port 10000)
resource "vultr_firewall_rule" "webmin" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "10000"
  notes             = "Webmin/Virtualmin HTTPS"
}

# SMTP
resource "vultr_firewall_rule" "smtp" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "25"
  notes             = "SMTP"
}

# SMTPS
resource "vultr_firewall_rule" "smtps" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "465"
  notes             = "SMTPS"
}

# Email Submission
resource "vultr_firewall_rule" "submission" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "587"
  notes             = "Email submission"
}

# IMAPS
resource "vultr_firewall_rule" "imaps" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "993"
  notes             = "IMAPS"
}

# POP3S
resource "vultr_firewall_rule" "pop3s" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "995"
  notes             = "POP3S"
}

# DNS
resource "vultr_firewall_rule" "dns_tcp" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "53"
  notes             = "DNS TCP"
}

resource "vultr_firewall_rule" "dns_udp" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "udp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "53"
  notes             = "DNS UDP"
}

# FTP
resource "vultr_firewall_rule" "ftp" {
  firewall_group_id = vultr_firewall_group.node.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "21"
  notes             = "FTP control"
}
