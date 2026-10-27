#!/usr/bin/perl
# Restore the Unix hash and native DB credential metadata without enabling the domain.
# Inputs arrive on stdin and are never included in command arguments or output.
use strict;
use warnings;
use JSON::PP qw(decode_json);

package virtual_server;
our ($first_print, $second_print, $indent_print, $outdent_print, $usermodule);

die "Recovery requires root\n" unless $> == 0;
my $input;
read(STDIN, $input, 32769);
die "Invalid recovery input\n" if !defined($input) || length($input) > 32768;
my $values = eval { JSON::PP::decode_json($input) };
die "Invalid recovery input\n" unless ref($values) eq 'HASH';
my ($domain, $owner, $id, $hash) = @{$values}{qw(domain owner domain_id credential_hash)};
my $action = $values->{'action'} || 'activate';
die "Invalid recovery action\n" unless $action eq 'activate' || $action eq 'verify-held';
die "Invalid recovery identity\n" unless defined($domain) && defined($owner) && defined($id)
    && $domain =~ /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/
    && $owner =~ /^[A-Za-z_][A-Za-z0-9_-]{0,31}$/ && $id =~ /^[0-9]{1,30}$/;
die "Invalid recovery credential\n" unless $action eq 'verify-held' || (defined($hash) && length($hash) <= 1024
    && $hash =~ /^(?:[!*]+|[!*]*\$[A-Za-z0-9][A-Za-z0-9.\/+_\$=-]*|[!*]*[A-Za-z0-9.\/]{13})$/);
my $credentials = $values->{'native_credentials'};
my @native_fields = qw(pass mysql_pass mysql_enc_pass disabled_oldmysql);
if ($action eq 'activate') {
    die "Invalid native recovery credentials\n" unless ref($credentials) eq 'HASH';
    foreach my $field (@native_fields) {
        die "Invalid native recovery credential\n" unless defined($credentials->{$field})
            && !ref($credentials->{$field}) && length($credentials->{$field}) <= 4096
            && $credentials->{$field} !~ /[\x00\r\n]/;
    }
}

$ENV{'WEBMIN_CONFIG'} = '/etc/webmin';
$ENV{'WEBMIN_VAR'} = '/var/webmin';
$main::no_acl_check = 1;
# Webmin derives its module from $0, even for a helper installed outside its module tree.
$0 = '/usr/share/webmin/virtual-server/praho-recovery-credentials.pl';
chdir('/usr/share/webmin/virtual-server') or die "Virtualmin is unavailable\n";
require './virtual-server-lib.pl';
$first_print = $second_print = $indent_print = $outdent_print = sub {};

my $succeeded;
my $stage = 'domain_lock';
my $failure = '';
{
    open(my $sink, '>', '/dev/null') or die "Recovery output could not be protected\n";
    local *STDOUT = $sink;
    local *STDERR = $sink;
    local $main::error_must_die = 1;
    $succeeded = eval {
        &lock_domain($id);
        $stage = 'domain_identity';
        my $d = &get_domain($id);
        die unless $d && $d->{'dom'} eq $domain && $d->{'user'} eq $owner
            && grep { $_ eq 'unix' } split(/,/, $d->{'disabled'} || '');
        $stage = 'unix_lock';
        &obtain_lock_unix($d);
        if ($action eq 'verify-held') {
            $stage = 'locked_shadow';
            &require_useradmin();
            my @users = &foreign_call($usermodule, 'list_users');
            my ($user) = grep { $_->{'user'} eq $owner } @users;
            die unless $user && defined($user->{'pass'}) && $user->{'pass'} =~ /^[!*]/;
        }
        else {
            my %old = %$d;
            $d->{'pass'} = '';
            $d->{'enc_pass'} = $hash;
            $d->{'pass_set'} = 1;
            $stage = 'native_callback';
            # This native callback has no boolean success contract; verify the state it updates.
            &modify_unix($d, \%old);
            die unless defined($d->{'disabled_oldpass'}) && $d->{'disabled_oldpass'} eq $hash;
            delete($d->{'pass_set'});
            # The existing-domain MySQL restore used the disabled placeholder's metadata.
            # Native enable_mysql later reads mysql_pass(), falling back to domain pass.
            # Preserve the archived native fields after the hash-only Unix callback, while
            # Unix remains locked. Only the later explicit enable invokes MySQL's callback.
            foreach my $field (@native_fields) {
                $d->{$field} = $credentials->{$field};
            }
            if (!$values->{'enabled'} && $d->{'mysql'} && !$d->{'parent'}) {
                # Restoring onto an already-disabled domain can recreate a usable SQL login,
                # while disable-domain skips its callback because the disabled flag is set.
                # Reapply the native suspension explicitly, then retain the archive's original
                # credential metadata for the eventual native billing unsuspension.
                $stage = 'mysql_lock';
                &obtain_lock_mysql($d);
                $stage = 'native_mysql_suspend';
                die unless &disable_mysql($d);
                &release_lock_mysql($d);
                foreach my $field (@native_fields) {
                    $d->{$field} = $credentials->{$field};
                }
            }
            $stage = 'domain_save';
            &save_domain($d);
        }
        &release_lock_unix($d);
        &unlock_domain($d);
        1;
    };
    $failure = $@ =~ /(Undefined subroutine [A-Za-z0-9_:]+ called)/ ? $1 : 'callback failed';
}
die "Recovery credential update failed ($stage; $failure)\n" unless $succeeded;
print "PRAHO_RECOVERY_CREDENTIALS_OK\n";
