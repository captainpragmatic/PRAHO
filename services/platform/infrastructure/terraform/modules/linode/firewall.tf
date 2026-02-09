# Linode Firewall Configuration
# Secures the hosting node with appropriate port access

resource "linode_firewall" "node" {
  label = "${var.hostname}-fw"

  linodes = [linode_instance.node.id]

  tags = ["praho", "deployment-${var.deployment_id}"]

  # SSH Access
  inbound {
    label    = "ssh"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "22"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # HTTP
  inbound {
    label    = "http"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "80"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # HTTPS
  inbound {
    label    = "https"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "443"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # Webmin/Virtualmin
  inbound {
    label    = "webmin"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "10000"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # Usermin
  inbound {
    label    = "usermin"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "20000"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # SMTP
  inbound {
    label    = "smtp"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "25"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # SMTPS
  inbound {
    label    = "smtps"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "465"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # Email Submission
  inbound {
    label    = "submission"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "587"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # IMAPS
  inbound {
    label    = "imaps"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "993"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # POP3S
  inbound {
    label    = "pop3s"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "995"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # DNS
  inbound {
    label    = "dns-tcp"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "53"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "dns-udp"
    action   = "ACCEPT"
    protocol = "UDP"
    ports    = "53"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # FTP
  inbound {
    label    = "ftp"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "21"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  # Default inbound policy: DROP
  inbound_policy = "DROP"

  # Allow all outbound
  outbound {
    label    = "all-tcp"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "1-65535"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  outbound {
    label    = "all-udp"
    action   = "ACCEPT"
    protocol = "UDP"
    ports    = "1-65535"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  outbound {
    label    = "icmp"
    action   = "ACCEPT"
    protocol = "ICMP"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  outbound_policy = "DROP"
}
