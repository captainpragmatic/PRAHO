# Outputs from Cloudflare DNS Module

output "a_record_id" {
  description = "Cloudflare A record ID"
  value       = cloudflare_record.node_a.id
}

output "a_record_hostname" {
  description = "Full hostname of A record"
  value       = cloudflare_record.node_a.hostname
}

output "aaaa_record_id" {
  description = "Cloudflare AAAA record ID (if created)"
  value       = length(cloudflare_record.node_aaaa) > 0 ? cloudflare_record.node_aaaa[0].id : null
}

output "aaaa_record_hostname" {
  description = "Full hostname of AAAA record (if created)"
  value       = length(cloudflare_record.node_aaaa) > 0 ? cloudflare_record.node_aaaa[0].hostname : null
}

output "mx_record_id" {
  description = "Cloudflare MX record ID (if created)"
  value       = length(cloudflare_record.node_mx) > 0 ? cloudflare_record.node_mx[0].id : null
}

output "spf_record_id" {
  description = "Cloudflare SPF TXT record ID (if created)"
  value       = length(cloudflare_record.node_spf) > 0 ? cloudflare_record.node_spf[0].id : null
}

output "dns_record_ids" {
  description = "List of all created DNS record IDs"
  value = compact([
    cloudflare_record.node_a.id,
    length(cloudflare_record.node_aaaa) > 0 ? cloudflare_record.node_aaaa[0].id : "",
    length(cloudflare_record.node_mx) > 0 ? cloudflare_record.node_mx[0].id : "",
    length(cloudflare_record.node_spf) > 0 ? cloudflare_record.node_spf[0].id : "",
  ])
}

output "fqdn" {
  description = "Fully qualified domain name"
  value       = cloudflare_record.node_a.hostname
}

output "email_records_created" {
  description = "Whether email records (MX, SPF) were created"
  value       = length(cloudflare_record.node_mx) > 0
}
