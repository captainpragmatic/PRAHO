#!/usr/bin/perl
use strict;
use warnings;
use JSON::PP ();
use Cwd ();
use Fcntl ();
use File::Basename ();
use File::Temp ();
use POSIX ();
use Storable ();
use Time::HiRes ();

package virtual_server;
our ($first_print, $second_print, $indent_print, $outdent_print);
our ($module_config_directory, $templates_dir, @list_templates_cache, %config);
die "Root required\n" unless $> == 0;
my $state_root = '/var/lib/praho/usage';
my $destination = '/var/log/praho/usage.log';
my $mode = @ARGV ? $ARGV[0] : '';
die "Unsupported usage operation\n" if @ARGV > 1 || $mode !~ /^(?:|reconcile|reconcile-hook|reconcile-locked)$/;
if ($mode eq 'reconcile-hook') {
    # Virtualmin waits for its post-command. Defer every telemetry mutation;
    # atomic replacement also preserves a new event during an active repair.
    usage_private_write("$state_root/reconciliation-pending", usage_now()." $$\n");
    print "PRAHO_USAGE_RECONCILIATION_DEFERRED\n";
    exit(0);
}
$ENV{'WEBMIN_CONFIG'} = '/etc/webmin';
$ENV{'WEBMIN_VAR'} = '/var/webmin';
$main::no_acl_check = 1;
$0 = '/usr/share/webmin/virtual-server/praho-usage-metadata.pl';
chdir('/usr/share/webmin/virtual-server') or die "Virtualmin unavailable\n";
require './virtual-server-lib.pl';
$first_print = $second_print = $indent_print = $outdent_print = sub {};

open(my $identity, '<', "$state_root/installation") or die "Usage identity unavailable\n";
my $installation = <$identity>;
close($identity);
chomp($installation);
die "Invalid usage identity\n" unless $installation =~ /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;

sub usage_now {
    my ($seconds, $microseconds) = Time::HiRes::gettimeofday();
    return POSIX::strftime('%Y-%m-%dT%H:%M:%S', gmtime($seconds)).sprintf('.%06d+00:00', $microseconds);
}

sub usage_top_id {
    my ($domain, $by_id) = @_;
    my %seen;
    while ($domain->{'parent'}) {
        die "Invalid hosting ownership\n" if $seen{$domain->{'id'}}++;
        $domain = $by_id->{$domain->{'parent'}} or die "Unknown hosting owner\n";
    }
    return "$domain->{'id'}";
}

sub usage_ports {
    my ($domain) = @_;
    my %seen;
    return grep { !$seen{$_}++ } (
        $domain->{'web_port'} || 80,
        $domain->{'ssl'} ? ($domain->{'web_sslport'} || 443) : ()
    );
}

sub usage_log_value {
    my ($top_id) = @_;
    return "$destination \"v1 $installation $top_id %{end:usec}t %B\"";
}

sub usage_owns_log {
    my ($value) = @_;
    my $words = &apache::wsplit($value);
    return $words && @$words && $words->[0] eq $destination;
}

sub usage_snapshot {
    my ($snapshots, $path) = @_;
    return if exists $snapshots->{$path};
    if (-e $path) {
        my @info = stat($path);
        my $contents = &read_file_contents($path);
        die "Native configuration cannot be read\n" unless defined($contents);
        $snapshots->{$path} = {contents => $contents, mode => $info[2] & 07777};
    }
    else { $snapshots->{$path} = undef; }
}

sub usage_restore {
    my ($snapshots) = @_;
    for my $path (keys %$snapshots) {
        my $before = $snapshots->{$path};
        if (defined $before) {
            &write_file_contents($path, $before->{'contents'});
            chmod($before->{'mode'}, $path) or die "Native configuration cannot be restored\n";
        }
        else { unlink($path) or die "Native configuration cannot be removed\n" if -e $path; }
    }
}

sub usage_private_write {
    my ($path, $contents) = @_;
    my ($file, $scratch) = File::Temp::tempfile('.usage-XXXXXXXX', DIR => File::Basename::dirname($path), UNLINK => 0);
    my $ok = eval {
        chmod(0600, $scratch) or die;
        print $file $contents or die;
        close($file) or die;
        rename($scratch, $path) or die;
        1;
    };
    unless ($ok) { close($file); unlink($scratch); die "Private usage state cannot be saved\n"; }
}

sub usage_read_bindings {
    my $contents = &read_file_contents("$state_root/bindings.json");
    my $state = defined($contents) ? eval { JSON::PP::decode_json($contents) } : undef;
    return {installation => $installation, accounts => {}}
        unless ref($state) eq 'HASH' && ($state->{'installation'} || '') eq $installation
            && ref($state->{'accounts'}) eq 'HASH';
    return $state;
}

sub usage_attest_bindings {
    my ($all, $by_id, $state, $reset) = @_;
    &require_apache();
    my $now = usage_now();
    my %result;
    for my $top (grep { !$_->{'parent'} && !$_->{'alias'} } @$all) {
        my $top_id = "$top->{'id'}";
        my $sites = 0;
        my %seen;
        my $valid = eval {
            for my $domain (grep { !$_->{'alias'} && ($_->{'web'} || $_->{'ssl'}) } @$all) {
                next unless usage_top_id($domain, $by_id) eq $top_id;
                for my $port (usage_ports($domain)) {
                    my ($virt, $members) = &get_apache_virtual($domain->{'dom'}, $port);
                    die "Missing hosting route\n" unless $virt;
                    next if $seen{"$virt->{'file'}:$virt->{'line'}"}++;
                    my @logs = grep { usage_owns_log($_) } &apache::find_directive('CustomLog', $members);
                    die "Private usage route is missing or duplicated\n" unless @logs == 1;
                    my $words = &apache::wsplit($logs[0]);
                    die "Private usage route has the wrong owner\n"
                        unless @$words == 2 && $words->[1] eq "v1 $installation $top_id %{end:usec}t %B";
                    $sites++;
                }
            }
            die "No observable hosting routes\n" unless $sites;
            1;
        };
        my $before = $state->{'accounts'}->{$top_id};
        my $started = $valid && ref($before) eq 'HASH' && $before->{'verified'} && !$reset->{$top_id}
            && ($before->{'started_at'} || '') =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$/
            ? $before->{'started_at'} : $now;
        $state->{'accounts'}->{$top_id} = {verified => $valid ? JSON::PP::true : JSON::PP::false,
            started_at => $started, last_seen_at => $now};
        $result{$top_id} = {binding_verified => $valid ? JSON::PP::true : JSON::PP::false,
            binding_started_at => $started};
    }
    my $cutoff = POSIX::strftime('%Y-%m-%dT%H:%M:%S', gmtime(time() - 90*86400));
    for my $id (keys %{$state->{'accounts'}}) {
        delete $state->{'accounts'}->{$id}
            if !exists($result{$id}) && ($state->{'accounts'}->{$id}->{'last_seen_at'} || '') lt $cutoff;
    }
    usage_private_write("$state_root/bindings.json", JSON::PP->new->canonical->encode($state));
    return \%result;
}

sub usage_template_edits {
    my ($raw_templates) = @_;
    my @edits;
    # Native creation normalizes every sub-server's parent to its top-level owner.
    my $owner = '${IF-PARENT}${PARENT}${ELSE-PARENT}${ID}${ENDIF-PARENT}';
    my $directive = 'CustomLog '.$destination.' "v1 '.$installation.' '.$owner.' %{end:usec}t %B"';
    for my $template (@$raw_templates) {
        my $web = $template->{'web'};
        next if !defined($web) || $web eq '' || $web eq 'none';
        die "Unsupported piped access log template\n" if $template->{'web_writelogs'};
        my @lines = grep { index($_, $destination) < 0 } split(/\t|\r?\n/, $web);
        my ($inserted, @output);
        for my $line (@lines) {
            if (!$inserted && $line =~ /^\s*(CustomLog|TransferLog)\s/) {
                push @output, $directive;
                $inserted = 1;
            }
            push @output, $line;
        }
        die "Unsupported access log template\n" unless $inserted;
        my $new = join("\t", @output);
        if ($new ne $web) { $template->{'web'} = $new; push @edits, $template; }
    }
    return @edits;
}

sub usage_save_template {
    my ($template) = @_;
    # Native save_template() also rewrites notification files and normalizes
    # unrelated defaults for IDs 0 and 1. Change only Apache's raw selector.
    my $path = $template->{'id'} == 0 ? "$module_config_directory/config" : "$templates_dir/$template->{'id'}";
    &lock_file($path);
    my $saved = eval {
        my %fresh;
        &read_file($path, \%fresh) or die "Native template unavailable\n";
        if ($template->{'id'} == 0) {
            $fresh{'apache_config'} = $template->{'web'};
            &save_module_config(\%fresh, 'virtual-server');
            %config = %fresh;
        }
        else {
            $fresh{'web'} = $template->{'web'};
            &write_file($path, \%fresh);
        }
        @list_templates_cache = ();
        1;
    };
    my $failure = $@;
    &unlock_file($path);
    die $failure unless $saved;
}

my $reconciling = $mode eq 'reconcile' || $mode eq 'reconcile-locked';
my $usage_lock;
my $reload_pending = 0;
if ($reconciling) {
    # The fixed reconcile-locked command is called only while Python owns this
    # lock. Deployment's explicit reconcile can wait for at most 20 seconds.
    if ($mode ne 'reconcile-locked') {
        sysopen($usage_lock, "$state_root/lock", Fcntl::O_CREAT() | Fcntl::O_RDWR() | Fcntl::O_NOFOLLOW(), 0600)
            or die "Usage lock unavailable\n";
        my $until = Time::HiRes::time() + 20;
        until (flock($usage_lock, Fcntl::LOCK_EX() | Fcntl::LOCK_NB())) {
            die "Usage collection is busy\n" if Time::HiRes::time() >= $until;
            Time::HiRes::sleep(0.05);
        }
    }
    $reload_pending = -e "$state_root/reconciliation-processing" || -e "$state_root/reconciliation-pending";
    # The hook writes only pending. Claiming by rename leaves a later event in
    # pending, even when it arrives while this repair is validating/reloading.
    if (-e "$state_root/reconciliation-pending") {
        rename("$state_root/reconciliation-pending", "$state_root/reconciliation-processing")
            or die "Usage reconciliation cannot be claimed\n";
    }
    usage_private_write("$state_root/reconciliation-processing", usage_now()." $$\n")
        unless -e "$state_root/reconciliation-processing";
}
my @all = &list_domains();
my %by_id = map { $_->{'id'} => $_ } @all;
my $binding_state = usage_read_bindings();
if ($reconciling) {
    local $main::error_must_die = 1;
    # Vhost lookup calls get_template(), which fills the native cache in place.
    # Capture raw inheritance selectors before any lookup, including in hooks.
    my $raw_templates;
    { local @list_templates_cache = (); $raw_templates = Storable::dclone([&list_templates()]); }
    my @edits = usage_template_edits($raw_templates);
    my %snapshots;
    my %config_before = %config;
    my %rebound;
    my $changed = 0;
    my $config_path = "$module_config_directory/config";
    usage_snapshot(\%snapshots, $config_path);
    usage_snapshot(\%snapshots, "$state_root/previous-hook");
    usage_snapshot(\%snapshots, "$state_root/bindings.json");
    for my $template (@edits) { usage_snapshot(\%snapshots, "$templates_dir/$template->{'id'}"); }
    &require_apache();
    my $ok = eval {
        my %seen;
        for my $domain (grep { !$_->{'alias'} && ($_->{'web'} || $_->{'ssl'}) } @all) {
            my $top_id = usage_top_id($domain, \%by_id);
            &obtain_lock_web($domain);
            my $updated = eval {
                for my $port (usage_ports($domain)) {
                    my ($virt, $members, $whole) = &get_apache_virtual($domain->{'dom'}, $port);
                    die "Hosting route is missing\n" unless $virt;
                    next if $seen{"$virt->{'file'}:$virt->{'line'}"}++;
                    my @old = &apache::find_directive('CustomLog', $members);
                    my @logs = grep { !usage_owns_log($_) } @old;
                    # Virtualmin reads the last CustomLog as its ordinary access log.
                    unshift @logs, usage_log_value($top_id);
                    next if join("\n", @old) eq join("\n", @logs);
                    usage_snapshot(\%snapshots, $virt->{'file'});
                    # Persist uncertainty before touching native configuration.
                    # A timeout or signal can interrupt before reload/attestation.
                    $binding_state->{'accounts'}->{$top_id} = {verified => JSON::PP::false,
                        started_at => usage_now(), last_seen_at => usage_now()};
                    usage_private_write("$state_root/bindings.json", JSON::PP->new->canonical->encode($binding_state));
                    &apache::save_directive('CustomLog', \@logs, $members, $whole);
                    &flush_file_lines($virt->{'file'});
                    $rebound{$top_id} = 1;
                    $changed++;
                }
                1;
            };
            my $failure = $@;
            &release_lock_web($domain);
            die $failure unless $updated;
        }
        for my $template (@edits) { usage_save_template($template); $changed++; }
        my $error = &apache::test_config();
        die "Apache configuration rejected\n" if defined($error);
        if ($changed || $reload_pending) { &restart_apache() or die "Apache reload failed\n"; }
        &lock_file($config_path);
        my $saved = eval {
            my %fresh;
            &read_file($config_path, \%fresh) or die "Native configuration unavailable\n";
            my $hook = '/usr/local/libexec/praho-usage-hook';
            if (($fresh{'post_command'} || '') ne $hook) {
                usage_private_write("$state_root/previous-hook", $fresh{'post_command'} || '');
                $fresh{'post_command'} = $hook;
                &save_module_config(\%fresh, 'virtual-server');
                $changed++;
            }
            1;
        };
        my $failure = $@;
        &unlock_file($config_path);
        die $failure unless $saved;
        usage_attest_bindings(\@all, \%by_id, $binding_state, \%rebound);
        1;
    };
    unless ($ok) {
        usage_restore(\%snapshots);
        %config = %config_before;
        @list_templates_cache = ();
        &apache::flush_config_cache() if defined(&apache::flush_config_cache);
        # A failed apply must leave the previous on-disk configuration in service.
        eval { &restart_apache() if $changed && !defined(&apache::test_config()); };
        die "Private usage logging could not be installed\n";
    }
    if (-e "$state_root/reconciliation-processing") {
        unlink("$state_root/reconciliation-processing") or die "Usage reconciliation cannot be completed\n";
    }
    print "PRAHO_USAGE_RECONCILED changed=$changed\n";
    exit(0);
}

my $bindings = usage_attest_bindings(\@all, \%by_id, $binding_state, {});
if (-e "$state_root/reconciliation-pending" || -e "$state_root/reconciliation-processing") {
    # Preserve healthy history in private state, but never attest a snapshot
    # while a concurrent or failed post-change repair is outstanding.
    $_->{'binding_verified'} = JSON::PP::false for values %$bindings;
}
my @rows;
for my $top (grep { !$_->{'parent'} && !$_->{'alias'} } @all) {
    my $top_id = "$top->{'id'}";
    my @members = grep { !$_->{'alias'} && usage_top_id($_, \%by_id) eq $top_id } @all;
    my $row = {id => $top_id, domain => "$top->{'dom'}", username => "$top->{'user'}", home => "$top->{'home'}",
        members => [map { "$_->{'id'}" } @members], mailboxes => (grep { $_->{'mail'} } @members) ? undef : 0,
        %{$bindings->{$top_id}}};
    my (@databases, %seen);
    my $ok;
    {
        # Native diagnostics can contain SQL or credentials. Only our allowlist
        # below may leave this process, including on unsupported storage profiles.
        open(my $sink, '>', '/dev/null') or die "Usage output cannot be protected\n";
        local *STDOUT = $sink;
        local *STDERR = $sink;
        local $main::error_must_die = 1;
        $ok = eval {
            my $home = Cwd::abs_path($top->{'home'});
            die "Unknown account storage\n" unless defined($home) && -d $home;
            for my $domain (@members) {
                my $child = Cwd::abs_path($domain->{'home'});
                die "Unsupported child storage\n" unless defined($child) && -d $child
                    && ($child eq $home || index($child, "$home/") == 0);
                for my $db (&domain_databases($domain, ['mysql', 'postgres'])) {
                    my $key = join("\0", $db->{'type'}, $db->{'host'} || '', $db->{'name'});
                    next if $seen{$key}++;
                    die "Unsupported storage\n" unless $db->{'type'} eq 'mysql';
                    my $path = &get_mysql_database_dir($domain, $db->{'name'});
                    die "Unknown storage\n" unless defined($path) && -d $path;
                    my ($bytes) = &mysql_size($domain, $db->{'name'}, 1);
                    die "Unknown allocation\n" unless defined($bytes) && $bytes >= 0;
                    push @databases, {path => $path, bytes => 0 + $bytes};
                }
            }
            1;
        };
    }
    if ($ok) { $row->{'databases'} = \@databases; }
    else { $row->{'unavailable'} = JSON::PP::true; }
    push @rows, $row;
}
print JSON::PP->new->canonical->encode({accounts => \@rows});
