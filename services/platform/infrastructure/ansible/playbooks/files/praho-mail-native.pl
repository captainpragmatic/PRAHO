#!/usr/bin/perl
# Fixed public projection and narrow backend selection; never print native domain/user hashes.
use strict;
use warnings;
use JSON::PP qw(decode_json encode_json);
use IPC::Open2 qw(open2);
use File::Basename qw(dirname);
use File::Temp qw(tempfile);
use Fcntl qw(O_RDONLY S_ISREG);
use IO::Handle;
use Digest::SHA qw(sha256_hex);
my $submitter_helper = dirname(__FILE__) . "/praho_mail_submitters.py";

package virtual_server;
our (%config, $module_config_file, $config_directory);
our ($first_print, $second_print, $indent_print, $outdent_print);
our $projection_stage = 'bootstrap';

sub run_projection {
my $input;
read(STDIN, $input, 32769);
my $values = eval { JSON::PP::decode_json($input // '') };
my $valid = $> == 0 && defined($input) && length($input) <= 32768 && ref($values) eq 'HASH';
my $action = $valid ? ($values->{'action'} // '') : '';
$valid &&= $action =~ /^(inventory|inspect_domain|select_backend|reconcile_submitters)$/;
my $result;
if ($valid) {
    local $main::error_must_die = 1;
    my $ok = eval {
        run_native_silenced(sub {
        $ENV{'WEBMIN_CONFIG'} = '/etc/webmin';
        $ENV{'WEBMIN_VAR'} = '/var/webmin';
        $main::no_acl_check = 1;
        $0 = '/usr/share/webmin/virtual-server/praho-mail-native.pl';
        chdir('/usr/share/webmin/virtual-server') or die;
        require './virtual-server-lib.pl';
        $first_print = $second_print = $indent_print = $outdent_print = sub {};
        if ($action eq 'inventory') {
            my @domains = &list_domains();
            die if @domains > 5000;
            my %mailboxes = &foreign_config('mailboxes');
            $result = {mail_default_off => ($config{'mail'} != 1 ? JSON::PP::true : JSON::PP::false),
                       mail_available => (defined($config{'mail'}) && $config{'mail'} == 2 ? JSON::PP::true : JSON::PP::false),
                       mail_backend_selected => (defined($config{'mail_system'}) && $config{'mail_system'} eq '0'
                         && defined($mailboxes{'mail_system'}) && $mailboxes{'mail_system'} eq '0' ? JSON::PP::true : JSON::PP::false),
                       domains => [map {{domain => $_->{'dom'}, mail_enabled => ($_->{'mail'} ? JSON::PP::true : JSON::PP::false)}} @domains]};
        }
        elsif ($action eq 'reconcile_submitters') {
            $result = reconcile_submitters($values);
        }
        elsif ($action eq 'select_backend') {
            # Change only mail capability/defaults and the two backend selectors. The general
            # set-global-feature command runs a whole-node check that also changes FTP/quotas.
            &lock_file($module_config_file);
            &save_module_config_keys({'mail_system' => 0, 'mail' => 2}, undef, 1);
            &unlock_file($module_config_file);
            &lock_file("$config_directory/mailboxes/config");
            my %mailboxes;
            &read_file("$config_directory/mailboxes/config", \%mailboxes) || die;
            $mailboxes{'mail_system'} = 0;
            &save_module_config(\%mailboxes, 'mailboxes');
            &unlock_file("$config_directory/mailboxes/config");
            $result = {selected => JSON::PP::true};
        }
        else {
            $result = project_domain($values);
        }
        1;
        });
        1;
    };
    $result = {error => 'mail_native_inspection_failed', stage => $projection_stage} unless $ok;
}
else {
    $result = {error => 'mail_native_inspection_failed'};
}
print JSON::PP::encode_json($result), "\n";
}
run_projection() unless caller;

sub project_domain {
    my ($request) = @_;
    my ($domain, $owner) = @{$request}{qw(domain owner)};
    die unless defined($domain) && defined($owner) && $domain =~ /^[a-z0-9][a-z0-9.-]{0,252}$/
        && $owner =~ /^[A-Za-z_][A-Za-z0-9_-]{0,31}$/ && $owner ne 'root';
    $projection_stage = 'domain_identity';
    my $d = &get_domain_by('dom', $domain);
    die unless $d && $d->{'user'} eq $owner && !$d->{'parent'} && !$d->{'alias'}
        && $d->{'id'} =~ /^[1-9][0-9]{0,19}$/;
    $projection_stage = 'owner_identity';
    my @owner = getpwnam($owner);
    die unless @owner && $owner[2] >= 1000 && $owner[2] == $d->{'uid'};
    $projection_stage = 'user_inventory';
    my @native_users = &list_domain_users($d, 0);
    die if @native_users > 1000;
    my (@users, %logins, %uids, %public_email);
    foreach my $user (@native_users) {
        next unless $user->{'email'};
        my ($login, $email) = @{$user}{qw(user email)};
        $projection_stage = 'user_shape';
        die unless $login =~ /^[A-Za-z0-9_][A-Za-z0-9_.\@-]{0,127}$/
            && $email =~ /^[A-Za-z0-9_.+%=-]{1,64}\@\Q$domain\E$/;
        $projection_stage = 'user_identity';
        my @native = getpwnam($login);
        die unless @native && $native[2] >= 1000 && $native[2] == $user->{'uid'}
            && !$logins{$login}++ && !$uids{$native[2]}++;
        $public_email{$login} = $email;
        push(@users, {login => $login, email => $email, uid => 0 + $native[2],
             enabled => ($d->{'mail'} && $user->{'pass'} && $user->{'pass'} !~ /^[!*]/ ? JSON::PP::true : JSON::PP::false)});
    }
    $projection_stage = 'alias_inventory';
    my @native_aliases = $d->{'mail'} ? &list_domain_aliases($d) : ();
    die if @native_aliases > 2000;
    my @aliases;
    foreach my $alias (@native_aliases) {
        $projection_stage = 'alias_shape';
        my $from = $alias->{'from'};
        die unless defined($from) && $from =~ /^(?:[A-Za-z0-9_.+%=-]{1,64})?\@\Q$domain\E$/;
        my $targets = $alias->{'to'};
        die unless ref($targets) eq 'ARRAY' && @$targets && @$targets <= 16;
        my @public_targets;
        foreach my $target (@$targets) {
            $projection_stage = 'alias_target';
            $target = $public_email{$target} if exists($public_email{$target});
            die unless defined($target) && length($target) <= 254
                && $target =~ /^[A-Za-z0-9_.+%=-]{1,64}\@[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/;
            push(@public_targets, $target);
        }
        push(@aliases, {address => $from, targets => \@public_targets});
    }
    my $dkim;
    $projection_stage = 'dkim';
    if ($d->{'mail'} && defined(&get_domain_dkim_key)) {
        my $path = &get_domain_dkim_key($d);
        if ($path && -f $path && !-l $path) {
            my @stat = stat($path);
            # Native Debian OpenDKIM owns generated per-domain keys as its system UID.
            # Root or that daemon may own them; customer UIDs and group/other access refuse.
            my @signer = getpwnam('opendkim');
            die unless @stat && ($stat[4] == 0 || (@signer && $signer[2] < 1000 && $stat[4] == $signer[2]))
                && ($stat[2] & 0077) == 0;
            my $cfg = &get_dkim_config();
            my $key = &get_dkim_dns_pubkey($cfg, $d);
            my $selector = $cfg->{'selector'};
            die unless $key && $key =~ /^[A-Za-z0-9+\/=]+$/ && length($key) <= 4096
                && $selector =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/;
            $dkim = {selector => $selector, record_name => "$selector._domainkey.$domain",
                     record_value => "v=DKIM1; k=rsa; p=$key"};
        }
    }
    return {domain => $domain, domain_id => "$d->{'id'}", owner => $owner, owner_uid => 0 + $owner[2],
            mail_enabled => ($d->{'mail'} ? JSON::PP::true : JSON::PP::false),
            users => \@users, aliases => \@aliases, dkim => $dkim};
}


sub reconcile_submitters {
    my ($request) = @_;
    my $zones = JSON::PP::decode_json($request->{'reserved_zones'} // '[]');
    die unless ref($zones) eq 'ARRAY' && @$zones && @$zones <= 64;
    foreach my $zone (@$zones) { die unless $zone =~ /^[a-z0-9][a-z0-9.-]{0,252}$/; }
    my @domains = sort { $a->{'id'} cmp $b->{'id'} } &list_domains();
    die if @domains > 5000;
    # Native domain mutation commands take these same locks. Re-read after waiting,
    # and retain the complete ordered set until the one-file authority swap finishes.
    foreach my $domain (@domains) { &lock_domain($domain); }
    @domains = map { &get_domain($_->{'id'}, undef, 1) || die } @domains;
    my %by_id = map { $_->{'id'}, $_ } @domains;
    my (@rows, $total);
    $total = 0;
    foreach my $d (@domains) {
        my $effective = $d->{'alias'} ? &get_domain($d->{'alias'}, undef, 1) : $d;
        die unless $effective;
        my $owner = $effective->{'user'};
        my @owner = getpwnam($owner);
        die unless @owner && $owner[2] >= 1000 && $owner[2] == $effective->{'uid'};
        my @users;
        if (!$d->{'alias'} && $d->{'mail'}) {
            my @native = &list_domain_users($d, 0, 0, 1, 1);
            die if @native > 1000;
            foreach my $u (@native) {
                next if $u->{'domainowner'} || $u->{'webowner'} || !$u->{'email'};
                my @actual = getpwnam($u->{'user'});
                die unless @actual && $actual[2] >= 1000 && $actual[2] == $u->{'uid'};
                push(@users, {login => $u->{'user'}, uid => 0 + $actual[2], email => $u->{'email'},
                  enabled => (!$d->{'disabled'} && $u->{'pass'} && $u->{'pass'} !~ /^[!*]/ ? JSON::PP::true : JSON::PP::false)});
            }
        }
        $total += @users;
        die if $total > 10000;
        push(@rows, {domain => $d->{'dom'}, owner => $owner, owner_uid => 0 + $owner[2],
          enabled => (submitter_enabled($d, \%by_id) ? JSON::PP::true : JSON::PP::false), users => \@users});
    }
    my $payload = JSON::PP::encode_json({domains => \@rows, reserved_zones => $zones});
    die if length($payload) > 2 * 1024 * 1024;
    my $pid = IPC::Open2::open2(my $reader, my $writer, '/usr/bin/python3', $submitter_helper);
    print {$writer} $payload or die;
    close($writer) or die;
    my $output = '';
    while (1) {
        my $size = read($reader, my $part, 65536);
        die unless defined($size);
        last unless $size;
        $output .= $part;
        die if length($output) > 2 * 1024 * 1024;
    }
    close($reader);
    waitpid($pid, 0);
    die if $? || !$output;
    # The lock-owning process performs the live rename. A renderer surviving its
    # parent can only write to a closed pipe, never publish authority after unlock.
    replace_submitter_map('/etc/postfix/praho-local-senders', $output);
    my $receipt = {maps_sha256 => Digest::SHA::sha256_hex($output)};
    foreach my $domain (reverse @domains) { &unlock_domain($domain); }
    return $receipt;
}


sub replace_submitter_map {
    my ($target, $content) = @_;
    my @before = lstat($target);
    die if @before && (!Fcntl::S_ISREG($before[2]) || $before[4] != $> || ($before[2] & 0022));
    my ($file, $temporary) = File::Temp::tempfile('.praho-senders-XXXXXXXX', DIR => File::Basename::dirname($target), UNLINK => 0);
    my $ok = eval {
        chmod(0644, $temporary) || die;
        binmode($file);
        print {$file} $content or die;
        $file->flush() || die;
        $file->sync() || die;
        close($file) || die;
        rename($temporary, $target) || die;
        sysopen(my $directory, File::Basename::dirname($target), Fcntl::O_RDONLY()) || die;
        $directory->sync() || die;
        close($directory);
        1;
    };
    unlink($temporary) if -e $temporary;
    die 'Sender map replacement failed' unless $ok;
}
1;

sub run_native_silenced {
    my ($callback) = @_;
    # Keep the real fd1/fd2 attached to Perl's standard handles. Rebinding their
    # globs to another fd breaks IPC::Open2 when a native action spawns a child.
    STDOUT->flush();
    STDERR->flush();
    open(my $saved_stdout, '>&', \*STDOUT) or die;
    open(my $saved_stderr, '>&', \*STDERR) or die;
    open(STDOUT, '>', '/dev/null') or die;
    open(STDERR, '>', '/dev/null') or die;
    my $value;
    my $ok = eval { $value = $callback->(); 1; };
    my $error = $@;
    STDOUT->flush();
    STDERR->flush();
    open(STDOUT, '>&', $saved_stdout) or die;
    open(STDERR, '>&', $saved_stderr) or die;
    die $error unless $ok;
    return $value;
}
1;

sub submitter_enabled {
    my ($domain, $by_id, $ancestors) = @_;
    die unless $domain && ref($by_id) eq 'HASH';
    my %path = %{$ancestors || {}};
    die if $path{$domain->{'id'}}++ || scalar(keys %path) > 16;
    my $enabled = !$domain->{'disabled'};
    foreach my $kind ('parent', 'alias') {
        next unless $domain->{$kind};
        my $ancestor = $by_id->{$domain->{$kind}} || die;
        my $ancestor_enabled = submitter_enabled($ancestor, $by_id, \%path);
        $enabled = 0 unless $ancestor_enabled;
    }
    return $enabled;
}
1;
