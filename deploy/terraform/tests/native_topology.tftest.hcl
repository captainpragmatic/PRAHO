mock_provider "hcloud" {
  override_during = plan
  mock_resource "hcloud_firewall" {
    defaults = { id = "12345" }
  }
  mock_resource "hcloud_server" {
    defaults = { id = "11001", ipv4_address = "192.0.2.10", ipv6_address = "2001:db8::10" }
  }
}

variables {
  hcloud_token         = "fixture-token"
  ssh_public_key       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture"
  firewall_ssh_sources = ["192.0.2.1/32"]
}

run "split_production" {
  command = plan
  variables {
    environment = "prod"
  }
  assert {
    condition     = output.server_count == 2
    error_message = "Production must default to split hosts."
  }
  assert {
    condition     = length(hcloud_server.portal[0].firewall_ids) == 1 && one(hcloud_server.portal[0].firewall_ids) == tonumber(hcloud_firewall.portal[0].id)
    error_message = "Portal must receive its own firewall."
  }
}

run "combined_staging" {
  command = plan
  variables {
    environment = "staging"
  }
  assert {
    condition     = output.server_count == 1
    error_message = "New staging must default to combined. Existing split staging requires explicit adoption."
  }
  assert {
    condition     = output.portal_ipv4 == output.platform_ipv4 && output.portal_ipv6 == output.platform_ipv6
    error_message = "Combined topology must expose the same actual ingress addresses for both roles."
  }
}

run "explicit_combined_production" {
  command = plan
  variables {
    environment     = "prod"
    native_topology = "combined"
  }
  assert {
    condition     = output.server_count == 1
    error_message = "Explicit combined production must remain supported."
  }
}

run "adopt_existing_split_staging" {
  command = plan
  variables {
    environment     = "staging"
    native_topology = "split"
  }
  assert {
    condition     = output.server_count == 2
    error_message = "Adoption must retain the existing Portal server address."
  }
}
