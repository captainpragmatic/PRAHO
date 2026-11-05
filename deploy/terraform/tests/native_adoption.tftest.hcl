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

# This fixture is the unmodified native infrastructure from master 51685587.
run "existing_two_server_staging" {
  state_key = "adoption"
  command   = apply
  module {
    source = "./tests/legacy_native"
  }
}

run "adopt_split_staging_without_replacing_servers" {
  state_key = "adoption"
  command   = plan
  variables {
    native_topology = "split"
  }
  assert {
    condition     = output.platform_server_id == run.existing_two_server_staging.platform_server_id && output.portal_server_id == run.existing_two_server_staging.portal_server_id
    error_message = "Adoption changed existing server identities."
  }
  assert {
    condition     = output.platform_ipv4 == run.existing_two_server_staging.platform_ipv4 && output.portal_ipv4 == run.existing_two_server_staging.portal_ipv4
    error_message = "Adoption changed existing public addresses."
  }
}

# Restore the unprotected fixture configuration solely for mocked test-state cleanup.
run "release_mock_fixture_state" {
  state_key = "adoption"
  command   = plan
  module {
    source = "./tests/legacy_native"
  }
}
