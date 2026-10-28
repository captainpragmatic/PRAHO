#!/usr/bin/perl
# Restore the Unix hash and native DB credential metadata without enabling the domain.
# Inputs arrive on stdin and are never included in command arguments or output.
use strict;
use warnings;
use JSON::PP qw(decode_json);
use MIME::Base64 qw(encode_base64 decode_base64);

package virtual_server;
use Fcntl qw(:flock :mode O_CREAT O_RDWR O_NOFOLLOW);
use Digest::SHA qw(sha256_hex);
our ($first_print, $second_print, $indent_print, $outdent_print, $usermodule);

die "Recovery requires root\n" unless $> == 0;
my $input;
read(STDIN, $input, 32769);
die "Invalid recovery input\n" if !defined($input) || length($input) > 32768;
my $values = eval { JSON::PP::decode_json($input) };
die "Invalid recovery input\n" unless ref($values) eq 'HASH';
my ($domain, $owner, $id, $hash) = @{$values}{qw(domain owner domain_id credential_hash)};
my $action = $values->{'action'} || 'activate';
die "Invalid recovery action\n" unless $action eq 'activate' || $action eq 'verify-held'
    || $action eq 'capture-owner' || $action eq 'reconcile-policy';
die "Invalid recovery identity\n" unless defined($domain) && defined($owner) && defined($id)
    && $domain =~ /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/
    && $owner =~ /^[A-Za-z_][A-Za-z0-9_-]{0,31}$/ && $id =~ /^[0-9]{1,30}$/;
die "Invalid recovery credential\n" unless $action ne 'activate' || (defined($hash) && length($hash) <= 1024
    && $hash =~ /^(?:[!*]+|[!*]*\$[A-Za-z0-9][A-Za-z0-9.\/+_\$=-]*|[!*]*[A-Za-z0-9.\/]{13})$/);
my $credentials = $values->{'native_credentials'};
my @native_fields = qw(pass mysql_pass mysql_enc_pass disabled_oldmysql);
my @aging_fields = qw(change min max warn inactive expire);
my $aging = $values->{'owner_shadow'};
if ($action eq 'activate' || defined($aging)) {
    die "Invalid owner shadow aging\n" unless ref($aging) eq 'HASH' && keys(%$aging) == 7
        && defined($aging->{'flag'}) && $aging->{'flag'} eq '';
    foreach my $field (@aging_fields) {
        die "Invalid owner shadow aging\n" unless defined($aging->{$field}) && !ref($aging->{$field})
            && $aging->{$field} =~ /^(?:|[0-9]{1,10})$/;
    }
}
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
my $policy_proof;
my $policy_fence_lock;
{
    open(my $sink, '>', '/dev/null') or die "Recovery output could not be protected\n";
    local *STDOUT = $sink;
    local *STDERR = $sink;
    local $main::error_must_die = 1;
    $succeeded = eval {
        if ($action eq 'reconcile-policy') {
            # Match the source barrier's lock order: migration fence, then
            # native domain/Unix locks. Never wait holding a domain lock.
            $stage = 'policy_source_fence';
            mkdir('/run/praho', 0700) unless -e '/run/praho';
            die if -l '/run/praho' || !-d '/run/praho';
            sysopen($policy_fence_lock, "/run/praho/migration-$id.lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0600) or die;
            flock($policy_fence_lock, LOCK_EX | LOCK_NB) or die;
            foreach my $path (glob("/var/lib/praho/migration/migration-$id.*.crontab")) {
                next unless $path =~ /\.([0-9a-f-]{36})\.crontab$/;
                die unless -e "/var/lib/praho/migration/migration-$id.$1.release-completed";
            }
        }
        &lock_domain($id);
        $stage = 'domain_identity';
        my $d = &get_domain($id);
        die unless $d && $d->{'dom'} eq $domain && $d->{'user'} eq $owner;
        die unless $action eq 'capture-owner' || $action eq 'reconcile-policy'
            || grep { $_ eq 'unix' } split(/,/, $d->{'disabled'} || '');
        $stage = 'unix_lock';
        &obtain_lock_unix($d);
        if ($action eq 'capture-owner') {
            $stage = 'owner_shadow_capture';
            my $archive = $values->{'archive'};
            die unless defined($archive) && ($archive =~ /^virtualmin_backup_[0-9a-f]{32}\.tar\.gz$/
                || $archive =~ /^migration_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tar\.gz$/);
            die if -e "/var/lib/praho-transfer/$archive" || -l "/var/lib/praho-transfer/$archive";
            &require_useradmin();
            die unless $usermodule eq 'useradmin';
            my @users = &foreign_call($usermodule, 'list_users');
            my ($user) = grep { $_->{'user'} eq $owner } @users;
            die unless $user && $user->{'uid'} == $d->{'uid'} && $user->{'gid'} == $d->{'gid'};
            if ($values->{'require_fenced'}) {
                die unless grep { $_ eq 'unix' } split(/,/, $d->{'disabled'} || '');
                die unless $user->{'pass'} =~ /^[!*]/;
            }
            # Native backup serialization samples the live Unix hash only for
            # enabled domains; disabled domains retain their original hash in
            # native metadata. Bind aging to that exact selected value, without
            # normalizing prefixes or replacing evidence on a repeated UUID.
            $stage = 'owner_shadow_credential_binding';
            my $credential = !$d->{'disabled'} ? $user->{'pass'}
                : exists($d->{'disabled_oldpass'}) ? $d->{'disabled_oldpass'} : $d->{'enc_pass'};
            die unless defined($credential) && length($credential) <= 1024
                && $credential =~ /^(?:[!*]+|[!*]*\$[A-Za-z0-9][A-Za-z0-9.\/+_\$=-]*|[!*]*[A-Za-z0-9.\/]{13})$/;
            my $credential_sha = sha256_hex($credential);
            my $key = 'praho_backup_owner_shadow_v1';
            my $profile;
            if ($d->{$key}) {
                my $previous = eval { JSON::PP::decode_json(MIME::Base64::decode_base64($d->{$key})) };
                die unless ref($previous) eq 'HASH';
                if (($previous->{'archive'} || '') eq $archive) {
                    die unless ($previous->{'domain'} || '') eq $domain && ($previous->{'owner'} || '') eq $owner
                        && ($previous->{'source_domain_id'} || '') eq $id && ($previous->{'version'} || 0) == 1
                        && ($previous->{'credential_sha256'} || '') eq $credential_sha;
                    # Capture is immutable for this archive, including before a delayed dispatch.
                    $profile = $previous;
                }
            }
            if (!$profile) {
                my %captured;
                foreach my $field (@aging_fields) {
                    my $value = defined($user->{$field}) ? "$user->{$field}" : '';
                    die unless $value =~ /^(?:|[0-9]{1,10})$/;
                    $captured{$field} = $value;
                }
                my %config = &foreign_config($usermodule);
                open(my $shadow, '<', $config{'shadow_file'}) or die;
                my @actual;
                while (my $line = <$shadow>) {
                    chomp($line);
                    my @fields = split(/:/, $line, -1);
                    @actual = @fields if $fields[0] eq $owner;
                }
                close($shadow);
                $stage = 'owner_shadow_reserved_flag';
                die unless @actual == 9 && $actual[8] eq '';
                $captured{'flag'} = '';
                $profile = {version => 1, domain => $domain, owner => $owner, source_domain_id => $id,
                            archive => $archive, aging => \%captured, credential_sha256 => $credential_sha};
            }
            $d->{$key} = MIME::Base64::encode_base64(JSON::PP::encode_json($profile), '');
            &save_domain($d);
        }
        elsif ($action eq 'reconcile-policy') {
            $stage = 'completed_policy_identity';
            my $operation = $values->{'operation_id'};
            my $scope = $values->{'activation_scope'};
            die unless defined($operation)
                && $operation =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
                && defined($scope) && ($scope eq 'recovery' || $scope eq 'bridge');
            die unless JSON::PP::is_bool($values->{'enabled'});
            my ($activation, $surface);
            if ($scope eq 'bridge') {
                my $directory = "/var/lib/praho/bridges/$operation";
                die if -e "$directory/origin-removed";
                $activation = read_private_json("$directory/activation.json");
                die unless ($activation->{'phase'} || '') eq 'completed';
                $surface = {domain => $activation->{'domain'}, owner => $activation->{'owner'},
                            domain_id => $activation->{'target_domain_id'}};
            }
            else {
                my $directory = '/var/lib/praho/recovery';
                $activation = read_private_json("$directory/$operation.activation");
                die unless ($activation->{'state'} || '') eq 'completed';
                $surface = read_private_json(-e "$directory/$operation.json"
                    ? "$directory/$operation.json" : "$directory/$operation.cleaned");
            }
            die unless ($surface->{'domain'} || '') eq $domain && ($surface->{'owner'} || '') eq $owner
                && ($surface->{'domain_id'} || '') eq $id;
            $stage = 'policy_native_state';
            die if $d->{'mail'};
            &require_useradmin();
            my @users = &foreign_call($usermodule, 'list_users');
            my ($before) = grep { $_->{'user'} eq $owner } @users;
            die unless $before;
            # Native useradmin callbacks do not retain the reserved shadow
            # flag. Refuse that unsupported current state before any mutation.
            my %shadow_config = &foreign_config($usermodule);
            open(my $shadow, '<', $shadow_config{'shadow_file'}) or die;
            my @actual;
            while (my $line = <$shadow>) {
                chomp($line);
                my @fields = split(/:/, $line, -1);
                @actual = @fields if $fields[0] eq $owner;
            }
            close($shadow);
            die unless @actual == 9 && $actual[8] eq '';
            my %before_aging = map { $_ => defined($before->{$_}) ? "$before->{$_}" : '' } @aging_fields;
            my $desired = $values->{'enabled'} ? 1 : 0;
            if ($desired) {
                # Active replay intentionally performs no native enable callback:
                # it must preserve customer-disabled jobs and current credentials.
                $stage = 'policy_enable_domain';
                die if $d->{'disabled'} && defined(&enable_virtual_server($d));
            }
            else {
                my $was_disabled = $d->{'disabled'} ? 1 : 0;
                my %prior = map { $_ => $d->{$_} } grep { exists($d->{$_}) }
                    (@native_fields, 'disabled_oldpass', 'disabled_shell');
                my $before_mysql;
                if ($d->{'mysql'} && !$d->{'parent'}) {
                    &require_mysql();
                    $before_mysql = &mysql_user_exists($d);
                }
                $stage = 'policy_disable_domain';
                die if defined(&disable_virtual_server($d, 'manual', 'PRAHO current service policy'));
                my %disabled = map { $_ => 1 } split(/,/, $d->{'disabled'} || '');
                foreach my $feature (qw(unix web ssl mysql webmin)) {
                    next unless $d->{$feature} && !$disabled{$feature};
                    $stage = "policy_disable_$feature";
                    my ($ok, $changed) = &try_function($feature, "disable_$feature", $d);
                    die unless $ok && $changed;
                    $disabled{$feature} = 1;
                }
                $d->{'disabled'} = join(',', sort keys %disabled);
                if ($was_disabled) {
                    # Repeating a native disable records the already-locked
                    # placeholder. Keep CURRENT saved credentials for later
                    # ordinary enable; never replay the archive's secret fields.
                    foreach my $field (@native_fields) {
                        next if $field eq 'disabled_oldmysql' && defined($before_mysql)
                            && $before_mysql ne ('0' x 41);
                        if (exists($prior{$field})) { $d->{$field} = $prior{$field}; }
                        else { delete($d->{$field}); }
                    }
                    if ($before->{'pass'} =~ /^[!*]/ && exists($prior{'disabled_oldpass'})) {
                        $d->{'disabled_oldpass'} = $prior{'disabled_oldpass'};
                    }
                    my ($nologin) = &get_common_available_shells();
                    if ($nologin && $before->{'shell'} eq $nologin->{'shell'} && exists($prior{'disabled_shell'})) {
                        $d->{'disabled_shell'} = $prior{'disabled_shell'};
                    }
                }
                $stage = 'policy_cron_fence';
                &disable_unix_cron_jobs($owner);
                &save_domain($d);
                @users = &foreign_call($usermodule, 'list_users');
                my ($held) = grep { $_->{'user'} eq $owner } @users;
                die unless $held && $held->{'pass'} =~ /^[!*]/;
            }
            $stage = 'policy_post_actions';
            die unless &run_post_actions();
            @users = &foreign_call($usermodule, 'list_users');
            my ($after) = grep { $_->{'user'} eq $owner } @users;
            die unless $after;
            $stage = 'policy_verify_aging';
            foreach my $field (@aging_fields) {
                die unless (defined($after->{$field}) ? "$after->{$field}" : '') eq $before_aging{$field};
            }
            $stage = 'policy_verify_enabled';
            die unless (!$d->{'disabled'}) == $desired;
            $policy_proof = {domain_id => $id, owner => $owner,
                             enabled => $desired ? JSON::PP::true : JSON::PP::false};
        }
        elsif ($action eq 'verify-held') {
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
            if (defined($aging)) {
                $stage = 'owner_shadow_restore';
                &require_useradmin();
                my @users = &foreign_call($usermodule, 'list_users');
                my ($user) = grep { $_->{'user'} eq $owner } @users;
                die unless $user && $user->{'uid'} == $d->{'uid'} && $user->{'gid'} == $d->{'gid'};
                my %restored = %$user;
                foreach my $field (@aging_fields) { $restored{$field} = $aging->{$field}; }
                &foreign_call($usermodule, 'modify_user', $user, \%restored);
                @users = &foreign_call($usermodule, 'list_users');
                my ($verified) = grep { $_->{'user'} eq $owner } @users;
                die unless $verified;
                foreach my $field (@aging_fields) {
                    die unless (defined($verified->{$field}) ? "$verified->{$field}" : '') eq $aging->{$field};
                }
            }
        }
        &release_lock_unix($d);
        &unlock_domain($d);
        1;
    };
    $failure = $@ =~ /(Undefined subroutine [A-Za-z0-9_:]+ called)/ ? $1 : 'callback failed';
}
die "Recovery credential update failed ($stage; $failure)\n" unless $succeeded;
# Native callbacks can change Perl's selected default output handle. The sink
# localization has ended; write explicitly to the restored controller stdout.
print STDOUT 'PRAHO_POLICY_RESULT='.MIME::Base64::encode_base64(JSON::PP::encode_json($policy_proof), '')."\n"
    if $policy_proof;
print STDOUT "PRAHO_RECOVERY_CREDENTIALS_OK\n";

sub read_private_json {
    my ($path) = @_;
    my @info = lstat($path);
    die unless @info && S_ISREG($info[2]) && $info[4] == 0 && !($info[2] & 077);
    open(my $file, '<', $path) or die;
    my $content;
    read($file, $content, 1048577);
    close($file);
    die unless defined($content) && length($content) <= 1048576;
    my $decoded = JSON::PP::decode_json($content);
    die unless ref($decoded) eq 'HASH';
    return $decoded;
}
