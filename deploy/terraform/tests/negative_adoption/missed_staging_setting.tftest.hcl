mock_provider "hcloud" {
  mock_resource "hcloud_server" {
    defaults = { id = "11001", ipv4_address = "192.0.2.10", ipv6_address = "2001:db8::1", status = "running" }
  }
  mock_resource "hcloud_firewall" {
    defaults = { id = "12001" }
  }
}

variables {
  hcloud_token         = "fixture-token"
  ssh_public_key       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture"
  firewall_ssh_sources = ["192.0.2.1/32"]
  environment          = "staging"
}

run "existing_split_staging" {
  state_key = "adoption"
  command   = apply
  module {
    source = "./tests/legacy_native"
  }
}

# This must fail with prevent_destroy. Omitting native_topology must never retire
# an existing Portal server when staging's new default is combined.
run "missed_staging_topology_must_fail" {
  state_key = "adoption"
  command   = plan
}
