#!/usr/bin/perl
# Change only Virtualmin quota metadata. All kernel mutations remain synchronous
# syscalls in the coordinator. Inherit its native account flock through completion.
use strict;
use warnings;
use JSON::PP ();
use Digest::SHA qw(sha256_hex);
use Fcntl qw(:flock);

die "Root quota metadata operation required\n" unless $> == 0 && @ARGV == 1 && $ARGV[0] =~ /^[0-9]{1,5}$/ && $ARGV[0] >= 3;
open(my $lane, '>&='.$ARGV[0]) or die "Native quota lane unavailable\n";
flock($lane, LOCK_EX | LOCK_NB) or die "Native quota lane unavailable\n";
my @held = stat($lane);
die "Private native quota lane required\n" unless @held && $held[4] == 0 && ($held[2] & 077) == 0;

my $input = '';
while (length($input) <= 16384) {
    my $count = read(STDIN, my $part, 16385 - length($input));
    die "Quota metadata input unreadable\n" unless defined($count);
    last unless $count;
    $input .= $part;
}
die "Quota metadata input exceeds bound\n" unless length($input) <= 16384;
my $request = eval { JSON::PP::decode_json($input) };
die "Invalid quota metadata request\n" unless ref($request) eq 'HASH';
my $identity = $request->{'identity'};
die "Invalid quota metadata identity\n" unless ref($identity) eq 'HASH';
my ($installation, $domain_id, $token) = @{$identity}{qw(installation domain_id)};
$token = $request->{'token'};
my $uuid = qr/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
die "Invalid quota metadata scope\n" unless defined($installation) && $installation =~ $uuid
    && defined($domain_id) && $domain_id =~ /^[0-9]{1,30}$/ && defined($token) && $token =~ $uuid;
my @current = stat('/run/praho/chain-'.$domain_id.'.lock');
die "Native quota lane identity changed\n" unless @current && $current[0] == $held[0] && $current[1] == $held[1];
my $scope = '/var/lib/praho/quotas/'.$installation.'/'.$domain_id;
die "Quota application cancelled\n" if -e $scope.'/cancelled-'.$token.'.json';
open(my $state_file, '<', $scope.'/current.json') or die "Quota application receipt unavailable\n";
my $state_text = do { local $/; <$state_file> };
close($state_file);
die "Invalid quota application receipt\n" unless defined($state_text) && length($state_text) <= 16384;
my $state = eval { JSON::PP::decode_json($state_text) };
my $digest = sha256_hex(JSON::PP->new->canonical->encode($request));
die "Quota application generation changed\n" unless ref($state) eq 'HASH'
    && ($state->{'phase'} || '') eq 'running' && ($state->{'token'} || '') eq $token
    && ($state->{'generation'} || 0) == ($request->{'generation'} || -1) && ($state->{'digest'} || '') eq $digest;
for my $quantity (qw(disk_limit_kib bandwidth_limit_bytes)) {
    die "Invalid quota metadata quantity\n" unless defined($request->{$quantity}) && !ref($request->{$quantity})
        && $request->{$quantity} =~ /^[0-9]{1,19}$/;
}

package virtual_server;
$main::no_acl_check = 1;
$ENV{'WEBMIN_CONFIG'} = '/etc/webmin';
$ENV{'WEBMIN_VAR'} = '/var/webmin';
$0 = '/usr/share/webmin/virtual-server/praho-quota-metadata.pl';
chdir('/usr/share/webmin/virtual-server') or die "Native Virtualmin unavailable\n";
require './virtual-server-lib.pl';
&lock_domain($domain_id);
my $ok = eval {
    my $domain = &get_domain($domain_id, undef, 1);
    die "Native quota domain changed\n" unless $domain && !$domain->{'parent'} && !$domain->{'alias'};
    for my $field (qw(id dom uid gid)) {
        my $expected = $field eq 'id' ? $identity->{'domain_id'} : $field eq 'dom' ? $identity->{'domain'} : $identity->{$field};
        die "Native quota ownership changed\n" unless defined($expected) && "$domain->{$field}" eq "$expected";
    }
    $domain->{'quota'} = $request->{'disk_limit_kib'};
    $domain->{'uquota'} = $request->{'disk_limit_kib'};
    $domain->{'bw_limit'} = $request->{'bandwidth_limit_bytes'};
    # The same synchronous child owns the inherited quota lane and native
    # domain lock; restored customer notification rows cannot outlive its fence.
    require '/usr/local/lib/praho/praho-notification-policy.pl';
    &virtual_server::praho_enforce_resource_policy($domain);
    &virtual_server::praho_enforce_domain_notifications($domain);
    &save_domain($domain) or die "Native quota metadata could not be saved\n";
    1;
};
my $error = $@;
&unlock_domain($domain_id);
die "Native quota metadata did not complete\n" unless $ok && !$error;
print "Quota metadata persisted\n";
