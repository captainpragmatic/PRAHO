#!/usr/bin/perl
# Change only Virtualmin quota metadata. All kernel mutations remain synchronous
# syscalls in the coordinator. Inherit its native account flock through completion.
use strict;
use warnings;
use JSON::PP ();
use Digest::SHA qw(sha256_hex);
use Fcntl qw(:flock);
use Time::Local qw(timegm);
use Time::HiRes ();

die "Root quota metadata operation required\n" unless $> == 0 && (@ARGV == 1 || (@ARGV == 2 && $ARGV[1] eq 'restore'))
    && $ARGV[0] =~ /^[0-9]{1,5}$/ && $ARGV[0] >= 3;
# restore: put back exactly the fields journalled before this same running application changed them (#776).
my $restore_mode = @ARGV == 2;
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
my $payload = eval { JSON::PP::decode_json($input) };
die "Invalid quota metadata request\n" unless ref($payload) eq 'HASH';
my ($request, $restore, $expected) = $restore_mode ? @{$payload}{qw(request restore expected)} : ($payload);
die "Invalid quota metadata request\n" unless ref($request) eq 'HASH';
my @restore_fields = qw(bw_limit bw_no_disable letsencrypt_email quota uquota);
if ($restore_mode) {
    # restore: the fields to write back; expected: what the apply child left, which must still be there.
    for my $image ($restore, $expected) {
        die "Invalid quota metadata restore\n" unless ref($image) eq 'HASH'
            && join(',', sort keys %$image) eq join(',', @restore_fields);
        for my $value (values %$image) {
            # A domain file holds one key=value per line: a newline, or anything but a short scalar, could add a field.
            die "Invalid quota metadata restore value\n" if defined($value)
                && (ref($value) || JSON::PP::is_bool($value) || $value !~ /^[\x20-\x7e]{0,255}$/);
        }
    }
}

sub metadata_image {
    my ($domain) = @_;
    return {map { ($_ => defined($domain->{$_}) ? "$domain->{$_}" : undef) } @restore_fields};
}
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
my $applied_images;
my $ok = eval {
    my $domain = &get_domain($domain_id, undef, 1);
    die "Native quota domain changed\n" unless $domain && !$domain->{'parent'} && !$domain->{'alias'};
    for my $field (qw(id dom uid gid)) {
        my $expected = $field eq 'id' ? $identity->{'domain_id'} : $field eq 'dom' ? $identity->{'domain'} : $identity->{$field};
        die "Native quota ownership changed\n" unless defined($expected) && "$domain->{$field}" eq "$expected";
    }
    my $images = {before => main::metadata_image($domain)};
    if ($restore_mode) {
        # Read under the domain lock: a field changed since the application (an administrator's edit) is never
        # overwritten. The caller keeps the outcome uncertain instead.
        for my $field (@restore_fields) {
            my ($current, $left) = ($images->{'before'}{$field}, $expected->{$field});
            die "Native quota metadata changed since the application\n"
                if defined($current) != defined($left) || (defined($current) && $current ne $left);
        }
        for my $field (@restore_fields) {
            if (defined($restore->{$field})) { $domain->{$field} = "$restore->{$field}"; }
            else { delete $domain->{$field}; }
        }
        &save_domain($domain) or die "Native quota metadata could not be restored\n";
        return 1;
    }
    my $policy = $request->{'policy'};
    if (defined($policy)) {
        die "Invalid quota overlay policy\n" unless ref($policy) eq 'HASH';
        my $expiry = $policy->{'expires_at'} || '';
        die "Invalid quota overlay expiry\n" unless $expiry =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?\+00:00$/;
        my $deadline = timegm($6, $5, $4, $3, $2 - 1, $1) + (defined($7) ? "0.$7" : 0);
        my $expired = $deadline <= Time::HiRes::time();
        die "Temporary quota overlay expired\n" if $policy->{'extra_mib'} && $expired;
        die "Quota overlay has not expired\n" if $policy->{'expiry_reduction'} && !$expired;
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
    $images->{'after'} = main::metadata_image($domain);
    $applied_images = $images;
    1;
};
my $error = $@;
&unlock_domain($domain_id);
die "Native quota metadata did not complete\n" unless $ok && !$error;
if ($restore_mode) { print "Quota metadata restored\n"; }
else {
    # The images the coordinator journals, so a later refusal can put back exactly what this child changed.
    print 'PRAHO_QUOTA_METADATA '.JSON::PP->new->canonical->encode($applied_images)."\n";
    print "Quota metadata persisted\n";
}
