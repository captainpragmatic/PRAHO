# PRAHO Ansible Infrastructure

Ansible playbooks and roles for automated Virtualmin GPL installation and server configuration.

## Structure

```
ansible/
├── ansible.cfg                  # Ansible configuration
├── requirements.yml             # Ansible Galaxy dependencies
├── group_vars/
│   └── all.yml                  # Global variables
├── inventory/
│   └── (dynamic inventory from PRAHO)
├── playbooks/
│   ├── common_base.yml          # Base server setup
│   ├── virtualmin.yml           # Virtualmin GPL installation
│   ├── virtualmin_harden.yml    # Security hardening
│   └── virtualmin_backup.yml    # Backup configuration
└── templates/
    ├── jail.local.j2            # Fail2ban configuration
    ├── 50unattended-upgrades.j2 # Auto-updates configuration
    ├── virtualmin_backup_schedule.j2
    └── domain_template.j2       # Virtualmin domain defaults
```

## Playbook Execution Order

For a new node deployment, playbooks are executed in this order:

1. **common_base.yml** - Basic server configuration
   - Package updates and installation
   - Hostname and timezone setup
   - SSH hardening
   - Swap configuration

2. **virtualmin.yml** - Virtualmin GPL installation
   - Downloads and runs install script
   - Configures Virtualmin settings
   - Sets PHP defaults
   - Generates Let's Encrypt certificate

3. **virtualmin_harden.yml** - Security hardening
   - Fail2ban installation and configuration
   - UFW firewall setup
   - Automatic security updates
   - System hardening (sysctl)

4. **virtualmin_backup.yml** - Backup setup
   - Local backup directory creation
   - Virtualmin scheduled backup configuration
   - Cleanup cron job for retention

## Variables

### Required Variables

These are typically passed from the NodeDeploymentService:

```yaml
# Deployment identification
deployment_id: "12345"
inventory_hostname: "prd-sha-het-de-fsn1-001"

# Backup settings
backup_enabled: true
backup_storage: "local"  # or "s3" (TODO)
backup_retention_days: 7
backup_schedule: "0 2 * * *"
```

### Default Variables (group_vars/all.yml)

```yaml
# System
system_timezone: "Europe/Bucharest"
system_swap_size_mb: 2048

# SSH
ssh_permit_root_login: "prohibit-password"
ssh_password_authentication: false

# Security
fail2ban_enabled: true
fail2ban_bantime: 3600
fail2ban_maxretry: 5

# PHP
php_default_version: "8.2"
php_memory_limit: "256M"
```

## Installation

Install Galaxy dependencies:

```bash
ansible-galaxy install -r requirements.yml
```

## Manual Testing

```bash
# Run against a specific host
ansible-playbook playbooks/common_base.yml -i "192.168.1.100," \
    --user root --private-key ~/.ssh/deployment_key \
    -e "inventory_hostname=test-server"

# Run full deployment
ansible-playbook playbooks/common_base.yml \
    playbooks/virtualmin.yml \
    playbooks/virtualmin_harden.yml \
    playbooks/virtualmin_backup.yml \
    -i "192.168.1.100," --user root --private-key ~/.ssh/deployment_key
```

## Pinned Versions

Virtualmin and Webmin versions are pinned in `playbooks/virtualmin.yml`:

```yaml
vars:
  virtualmin_version: "7.10.0"
  webmin_version: "2.105"
```

Update these when upgrading to new versions. Test thoroughly before deploying.

## Security Considerations

- Root login is key-only (no password)
- SSH password authentication is disabled
- Fail2ban protects SSH, Webmin, mail, FTP, web
- UFW provides host-level firewall (backup to cloud firewall)
- Automatic security updates enabled
- Let's Encrypt certificate for Webmin HTTPS

## TODO

- [ ] S3 backup destination support
- [ ] Multi-PHP version installation
- [ ] Custom firewall rules via variables
- [ ] Prometheus/Grafana monitoring integration
