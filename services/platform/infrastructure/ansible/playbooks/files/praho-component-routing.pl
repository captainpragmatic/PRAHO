#!/usr/bin/perl
# Exact local-zone updates through pinned Virtualmin locks; no whole-domain DNS-IP callback.
package virtual_server;
use strict;
use warnings;
use JSON::PP qw(decode_json encode_json);
use IPC::Open3;
use Symbol qw(gensym);
use File::Basename qw(dirname);
our ($first_print, $second_print, $indent_print, $outdent_print);
die "Native routing requires root" unless $> == 0;
my $encoded; { local $/; $encoded = <STDIN>; }
die "Oversized native routing request" unless defined($encoded) && length($encoded) <= 1048576;
my $payload = decode_json($encoded);
my $request = $payload->{'request'};
die "Invalid native routing identity" unless $request->{'domain_id'} =~ /^[0-9]{1,30}$/ &&
    $request->{'domain'} =~ /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/ &&
    $request->{'owner'} =~ /^[A-Za-z_][A-Za-z0-9_-]{0,31}$/;
my $planner = dirname($0)."/praho-component-routing.py";
$main::no_acl_check++;
$ENV{'WEBMIN_CONFIG'} = '/etc/webmin'; $ENV{'WEBMIN_VAR'} = '/var/webmin';
$0 = '/usr/share/webmin/virtual-server/modify-dns.pl';
chdir('/usr/share/webmin/virtual-server') or die "Native module unavailable";
require './virtual-server-lib.pl';
$first_print = $second_print = $indent_print = $outdent_print = sub {};
my $domain = &get_domain($request->{'domain_id'});
die "Native routing identity changed" unless $domain && $domain->{'dom'} eq $request->{'domain'} &&
    $domain->{'user'} eq $request->{'owner'} && !$domain->{'parent'} && !$domain->{'alias'};
if (!$domain->{'dns'} || $domain->{'dns_cloud'} || $domain->{'dns_remote'} || $domain->{'dns_submode'} ||
    $domain->{'provision_dns'} || &copy_alias_records($domain)) {
    print encode_json({'mode' => 'operator_dns_required'}); exit 0;
}
# post_records_change also synchronizes copied alias ZONES. Those names are
# outside the approved apex/www scope, so never enter its publication path.
my @copied_aliases=grep { $_->{'dns'} && !$_->{'aliasdns'} } &get_domain_by('alias', $domain->{'id'});
if (@copied_aliases) {
    print encode_json({'mode' => 'operator_dns_required'}); exit 0;
}
sub python {
    my ($action, $data) = @_;
    my ($input, $output); my $errors = gensym;
    my $pid = open3($input, $output, $errors, '/usr/bin/python3', $planner, $action);
    print $input encode_json($data); close $input;
    my $text; { local $/; $text = <$output>; } close $output;
    my $error; { local $/; $error = <$errors>; } close $errors;
    waitpid($pid, 0);
    die "Native routing planner failed" if $? || !defined($text) || length($text) > 1048576;
    return $text;
}
&obtain_lock_dns($domain);
my ($frozen, $mode, $error);
eval {
    &pre_records_change($domain); $frozen = 1;
    my ($records, $file) = &get_domain_dns_records_and_file($domain, 1);
    die "Native DNS records unavailable" unless ref($records) eq 'ARRAY' && defined($file);
    my $plan = decode_json(python('--plan', {'domain' => $domain->{'dom'}, 'records' => $records,
                                          'network' => $payload->{'network'}}));
    $mode = $plan->{'mode'};
    if ($mode eq 'source_dns_updated' && @{$plan->{'operations'}}) {
        my @original = @$records;
        for my $operation (@{$plan->{'operations'}}) {
            if ($operation->{'create'}) {
                &create_dns_record($records, $file, $operation->{'create'});
            } else {
                my $record = $original[$operation->{'index'}];
                if (length($operation->{'value'})) {
                    $record->{'values'} = [$operation->{'value'}];
                    &modify_dns_record($records, $file, $record);
                } else {
                    &delete_dns_record($records, $file, $record);
                }
            }
        }
        my $post_error = &post_records_change($domain, $records, $file);
        die "Native DNS publication failed" if $post_error;
        &reload_bind_records($domain);
        my ($current) = &get_domain_dns_records_and_file($domain, 1);
        my $digest = python('--retained', {'domain' => $domain->{'dom'}, 'records' => $current});
        chomp $digest;
        die "Retained DNS records changed" unless $digest eq $plan->{'retained_digest'};
    }
};
$error = $@;
&after_records_change($domain) if $frozen;
&release_lock_dns($domain);
die $error if $error;
&run_post_actions();
print encode_json({'mode' => $mode});
