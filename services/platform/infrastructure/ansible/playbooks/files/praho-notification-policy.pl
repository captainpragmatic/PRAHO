#!/usr/bin/perl
# Virtualmin 8.3 customer notification ownership. No MTA or tenant-content changes.
package virtual_server;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use Fcntl qw(S_ISREG O_RDONLY O_NOFOLLOW);
use IO::Handle;

sub praho_probe_identity_file {
    my ($path, $value) = @_;
    if (defined($value)) {
        my $temporary=$path.'.tmp';
        open(my $out,'>',$temporary) or die 'Cannot reserve isolated probe provenance';
        chmod(0600,$temporary) or die 'Cannot protect isolated probe provenance';
        print $out JSON::PP->new->canonical->encode($value);
        $out->flush() && $out->sync() or die 'Cannot persist isolated probe provenance';
        close($out) or die 'Cannot finish isolated probe provenance';
        rename($temporary,$path) or die 'Cannot activate isolated probe provenance';
        return $value;
    }
    return undef if !-e $path && !-l $path;
    my @info=lstat($path);
    die 'Unprotected isolated probe provenance' if !@info || !S_ISREG($info[2]) || $info[4] || ($info[2]&0077);
    open(my $in,'<',$path) or die 'Cannot read isolated probe provenance';
    my $raw=do {local $/;<$in>};close($in);
    die 'Oversized isolated probe provenance' if length($raw)>65536;
    return JSON::PP->new->decode($raw);
}

sub praho_reserve_probe_identity {
    my $name='praho-quota-probe';my $file='/var/lib/praho/hosting/probe-identity.json';
    my $installation_file=-e '/var/lib/praho/usage/installation' ? '/var/lib/praho/usage/installation' : '/etc/machine-id';
    my @info=lstat($installation_file);
    die 'Unknown native installation identity' if !@info || !S_ISREG($info[2]) || $info[4] || ($info[2]&0022);
    open(my $identity,'<',$installation_file) or die 'Cannot read native installation identity';
    my $installation=do {local $/;<$identity>};close($identity);$installation=~s/\s+\z//;
    $installation=~s/\A([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{12})\z/$1-$2-$3-$4-$5/;
    die 'Invalid native installation identity' if $installation!~/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/;
    &require_useradmin();die 'Isolated probe requires local Unix accounts' if $usermodule ne 'useradmin' || $config{'ldap'};
    &obtain_lock_unix();
    my $reservation=&praho_probe_identity_file($file);
    my @user=getpwnam($name);my @group=getgrnam($name);
    die 'Existing native name has no isolated probe provenance' if !$reservation && (@user || @group);
    my (%uids,%users,%gids,%groups);&build_taken(\%uids,\%users);&build_group_taken(\%gids,\%groups);
    if (!$reservation) {
        my ($id)=grep {!$uids{$_} && !$gids{$_}} (2147000000..2147000031);
        die 'No reserved native probe identity is available' if !defined($id);
        $reservation={schema=>1,name=>$name,uid=>$id,gid=>$id,state=>'creating',installation=>$installation};
        &praho_probe_identity_file($file,$reservation);
    }
    my $id=$reservation->{'uid'};
    die 'Unknown isolated native identity provenance' if ref($reservation) ne 'HASH' || keys(%$reservation)!=6
        || $reservation->{'schema'}!=1 || $reservation->{'name'} ne $name || $id!~/\A[0-9]+\z/
        || $id<2147000000 || $id>2147000031 || $reservation->{'gid'}!=$id
        || $reservation->{'installation'} ne $installation
        || $reservation->{'state'}!~/\A(?:creating|reserved)\z/;
    my @allusers=&list_all_users();my @allgroups=&list_all_groups();
    die 'Reserved probe UID or GID belongs to another account'
        if grep {$_->{'uid'}==$id && $_->{'user'} ne $name} @allusers;
    die 'Reserved probe group belongs to another account'
        if grep {$_->{'gid'}==$id && $_->{'group'} ne $name} @allgroups;
    if (!@group) {&foreign_call('useradmin','create_group',{group=>$name,gid=>$id,members=>''});}
    if (!@user) {&foreign_call('useradmin','create_user',{user=>$name,uid=>$id,gid=>$id,pass=>'!',
        real=>'PRAHO isolated quota probe',home=>'/nonexistent',shell=>'/usr/sbin/nologin'});}
    @user=getpwnam($name);@group=getgrnam($name);
    die 'Reserved probe account drift requires operator review' if !@user || !@group || $user[2]!=$id
        || $user[3]!=$id || $group[2]!=$id || $user[6] ne 'PRAHO isolated quota probe'
        || $user[7] ne '/nonexistent' || $user[8] ne '/usr/sbin/nologin' || $group[3] ne '' || -e '/nonexistent';
    undef(@useradmin::list_users_cache);
    my ($shadow)=grep {$_->{'user'} eq $name} &useradmin::list_users();
    die 'Reserved probe password must remain locked' if !$shadow || $shadow->{'pass'}!~/\A[!*]/;
    $reservation->{'state'}='reserved';&praho_probe_identity_file($file,$reservation);
    &release_lock_unix();
    return {uid=>0+$id,gid=>0+$id};
}

sub praho_addresses {
    my ($value) = @_;
    return () if !defined($value) || $value eq '' || $value eq 'none';
    $value = $gconfig{'webmin_email_to'} if $value eq '*';
    return map { lc($_) } &extract_address_parts($value) if defined(&extract_address_parts);
    # Standalone policy contract test; Virtualmin supplies its complete address parser in production.
    return map { lc($_) } split(/[\s,]+/, $value);
}

sub praho_global_operators {
    return &unique(map { &praho_addresses($_) } ($gconfig{'webmin_email_to'}, @config{qw(quota_email bw_email backup_email statusemail)},
        grep { /\@/ } split(/\s+/, $config{'scriptwarn_email'})));
}

sub praho_operator_policy {
    my ($replace, $extra) = @_;
    my $file = '/var/lib/praho/hosting/operators.json';
    if (!$replace && -f $file) {
        open(my $in, '<', $file) or die 'Cannot read approved operator policy';
        local $/;
        my $raw = <$in>;
        die 'Oversized approved operator policy' if length($raw) > 65536;
        close($in);
        my $operators = JSON::PP->new->decode($raw);
        die 'Invalid approved operator policy' if ref($operators) ne 'ARRAY';
        return $operators;
    }
    my @operators = &unique(&praho_global_operators(), @$extra);
    return \@operators if !$replace;
    my $temporary = $file . '.tmp';
    open(my $out, '>', $temporary) or die 'Cannot persist approved operator policy';
    chmod(0600, $temporary) or die 'Cannot protect approved operator policy';
    print $out JSON::PP->new->canonical->encode(\@operators);
    close($out) or die 'Cannot finish approved operator policy';
    rename($temporary, $file) or die 'Cannot activate approved operator policy';
    return \@operators;
}

sub praho_template_policy {
    my ($t, $operators) = @_;
    $operators ||= &praho_operator_policy(0, []);
    my %allowed = map { lc($_) => 1 } @$operators;
    $t->{$_} = 'none' for qw(mail_on newuser_on updateuser_on);
    $t->{$_} = '' for qw(mail_cc mail_bcc newuser_cc newuser_bcc updateuser_cc updateuser_bcc);
    $t->{$_} = 0 for qw(newuser_to_mailbox newuser_to_owner newuser_to_reseller updateuser_to_mailbox updateuser_to_owner updateuser_to_reseller);
    $t->{'ssl_email'} = 2;
    $t->{'statusonly'} = 1;
    $t->{'status'} = join(',', grep { $allowed{lc($_)} } &praho_addresses($t->{'status'})) || 'none';
    return $t;
}

# Called only inside the quota metadata child's validated native claim and domain lock.
# The surrounding caller persists the exact freshly reread domain. No child/hook escapes its FD.
sub praho_enforce_resource_policy {
    my ($domain) = @_;
    die 'Native automatic bandwidth actions require node policy repair' if $config{'bw_disable'} || $config{'bw_enable'};
    $domain->{'bw_no_disable'} = 1;
}

sub praho_apply_resource_policy {
    &save_module_config_keys({bw_disable=>0,bw_enable=>0});
    $config{'bw_disable'}=0;$config{'bw_enable'}=0;
    for my $domain (&list_domains()) {
        &lock_domain($domain);
        my $fresh=&get_domain($domain->{'id'},undef,1);
        die 'Native domain vanished during resource adoption' if !$fresh;
        &praho_enforce_resource_policy($fresh);
        &save_domain($fresh) or die 'Native resource policy could not be persisted';
        &unlock_domain($fresh);
    }
}

sub praho_native_customer_notifications {
    my $owner = '/var/lib/praho/hosting/notification-owner';
    return 1 if !-e $owner && !-l $owner;
    my @info = lstat($owner);
    die 'Unprotected native notification ownership' if !@info || !S_ISREG($info[2]) || $info[4]
        || ($info[2] & 0022) || !($info[2] & 0400);
    sysopen(my $in, $owner, O_RDONLY | O_NOFOLLOW) or die 'Cannot read native notification ownership';
    my @opened = stat($in);
    die 'Native notification ownership changed' if !@opened || $opened[0] != $info[0] || $opened[1] != $info[1];
    my $count = read($in, my $current, 65);
    close($in);
    die 'Unknown native notification owner' if !defined($count) || $current ne "platform\n";
    return 0;
}

sub praho_enforce_domain_notifications {
    my ($domain) = @_;
    return if &praho_native_customer_notifications(); # Import/kernel adoption never implies handover.
    die 'Approved operator policy is missing' if !-f '/var/lib/praho/hosting/operators.json';
    my $operators = &praho_operator_policy(0, []);
    my %allowed = map { lc($_) => 1 } @$operators;
    for my $key (qw(quota_users quota_mailbox_send bw_owner bw_disable bw_enable)) {
        die 'Native global customer-mail policy drift requires node review' if $config{$key};
    }
    for my $key (qw(domain_template subdomain_template user_template update_template)) {
        die 'Native template defaults drift requires node review' if $config{$key} ne 'none';
    }
    local *ensure_template = sub { };
    my $template = &get_template($domain->{'template'});
    die 'Restored domain template is unknown' if !$template;
    for my $key (qw(mail_on newuser_on updateuser_on)) {
        die 'Restored shared template requires explicit node review' if $template->{$key} ne 'none';
    }
    for my $key (qw(mail_cc mail_bcc newuser_cc newuser_bcc updateuser_cc updateuser_bcc newuser_to_mailbox newuser_to_owner newuser_to_reseller updateuser_to_mailbox updateuser_to_owner updateuser_to_reseller)) {
        die 'Restored template recipient bypass requires explicit node review' if $template->{$key};
    }
    die 'Restored monitor template requires node review' if !$template->{'statusonly'}
        || grep { !$allowed{$_} } &praho_addresses($template->{'status'});
    $domain->{'letsencrypt_email'} = 2;
    &foreign_require('status');
    for my $monitor (&status::list_services()) {
        next if ($monitor->{'virtualmin'} // '') ne $domain->{'id'};
        $monitor->{'email'} = join(',', grep { $allowed{$_} } &praho_addresses($monitor->{'email'}));
        &status::save_service($monitor);
    }
}

sub praho_notification_inventory {
    # list_templates normally copies missing default message bodies to config.
    # Read-only inventory needs only flags, and must not materialize those files.
    local *ensure_template = sub { };
    my %operators = map { lc($_) => 1 } @{&praho_operator_policy(0, [])};
    my @templates = &list_templates();
    my @domains = &list_domains();
    my @backups = &list_scheduled_backups();
    &foreign_require('status');
    my @monitors = &status::list_services();
    my %owners = map { lc($_) => 1 } map { &extract_address_parts($_->{'emailto'}) } @domains;
    my %emitters = map { $_ => JSON::PP::true } qw(domain_signup new_users updated_users quota_warnings bandwidth_warnings bandwidth_actions backup_owners acme_owners application_warnings status_monitors);
    my @inventory;
    for my $raw (@templates) {
        my $t = &get_template($raw->{'id'}); # Inspect effective inherited settings, including standard sub-server defaults.
        $emitters{'domain_signup'} = JSON::PP::false if $t->{'mail_on'} ne 'none' || $t->{'mail_cc'} || $t->{'mail_bcc'};
        $emitters{'new_users'} = JSON::PP::false if $t->{'newuser_on'} ne 'none' || grep { $t->{$_} } qw(newuser_cc newuser_bcc newuser_to_mailbox newuser_to_owner newuser_to_reseller);
        $emitters{'updated_users'} = JSON::PP::false if $t->{'updateuser_on'} ne 'none' || grep { $t->{$_} } qw(updateuser_cc updateuser_bcc updateuser_to_mailbox updateuser_to_owner updateuser_to_reseller);
        $emitters{'acme_owners'} = JSON::PP::false if $t->{'ssl_email'} ne '2';
        $emitters{'status_monitors'} = JSON::PP::false if !$t->{'statusonly'} || grep { !$operators{$_} } &praho_addresses($t->{'status'});
        push @inventory, { type => 'template', map { $_ => $t->{$_} // '' } qw(id mail_on mail_cc mail_bcc newuser_on newuser_cc newuser_bcc newuser_to_mailbox newuser_to_owner newuser_to_reseller updateuser_on updateuser_cc updateuser_bcc updateuser_to_mailbox updateuser_to_owner updateuser_to_reseller ssl_email statusonly status) };
    }
    for my $d (@domains) {
        $emitters{'acme_owners'} = JSON::PP::false if ($d->{'letsencrypt_email'} // '0') ne '2';
        push @inventory, { type => 'domain', map { $_ => $d->{$_} // '' } qw(id template emailto letsencrypt_email letsencrypt_email_master) };
    }
    for my $b (@backups) {
        $emitters{'backup_owners'} = JSON::PP::false if $b->{'email_doms'}
            || grep { !$operators{$_} } &praho_addresses($b->{'email'});
        push @inventory, { type => 'backup', map { $_ => $b->{$_} // '' } qw(id email_doms email email_err) };
    }
    for my $m (@monitors) {
        next if !$m->{'virtualmin'};
        $emitters{'status_monitors'} = JSON::PP::false if grep { !$operators{$_} } &praho_addresses($m->{'email'});
        push @inventory, { type => 'monitor', map { $_ => $m->{$_} // '' } qw(id virtualmin email) };
    }
    $emitters{'quota_warnings'} = JSON::PP::false if $config{'quota_users'} || $config{'quota_mailbox_send'};
    $emitters{'bandwidth_warnings'} = JSON::PP::false if $config{'bw_owner'};
    $emitters{'bandwidth_actions'} = JSON::PP::false if $config{'bw_disable'} || $config{'bw_enable'};
    $emitters{'application_warnings'} = JSON::PP::false if $config{'scriptwarn_enabled'} || &find_cron_script($scriptwarn_cron_cmd)
        || grep { ! $operators{$_} } &praho_addresses($config{'scriptwarn_email'});
    push @inventory, { type => 'config', map { $_ => $config{$_} // '' } qw(domain_template subdomain_template user_template update_template quota_users quota_mailbox_send quota_email bw_owner bw_email bw_disable bw_enable backup_email_doms ssl_email scriptwarn_enabled statusonly statusemail) };
    my $json = JSON::PP->new->canonical;
    return { evidence => { emitters => \%emitters, operator_alerts_preserved => JSON::PP::true, tenant_mail_preserved => JSON::PP::true },
        bandwidth_policy => {auto_disable=>$config{'bw_disable'} ? JSON::PP::true : JSON::PP::false,
                             auto_enable=>$config{'bw_enable'} ? JSON::PP::true : JSON::PP::false},
        inventory_digest => sha256_hex($json->encode(\@inventory)) };
}

sub praho_apply_notification_policy {
    my ($operators) = @_;
    # Domain ownership and global config are locked by the synchronous coordinator's node operation.
    my %changes = (domain_template => 'none', subdomain_template => 'none', user_template => 'none', update_template => 'none', quota_users => 0, quota_mailbox_send => 0, bw_owner => 0, bw_disable => 0, bw_enable => 0, backup_email_doms => 0, ssl_email => 2, scriptwarn_enabled => 0, statusonly => 1);
    my %allowed_scripts = map { lc($_) => 1 } @$operators;
    $changes{'scriptwarn_email'} = join(' ', grep { $allowed_scripts{$_} } &praho_addresses($config{'scriptwarn_email'}));
    &save_module_config_keys(\%changes);
    $config{$_} = $changes{$_} for keys %changes;
    for my $t (&list_templates()) {
        &praho_template_policy($t, $operators);
        &save_template($t);
    }
    for my $b (&list_scheduled_backups()) {
        my %approved = map { lc($_) => 1 } @$operators;
        my @addresses = &praho_addresses($b->{'email'});
        my $unapproved = grep { !$approved{$_} } @addresses;
        next if !$b->{'email_doms'} && !$unapproved;
        $b->{'email_doms'} = 0;
        $b->{'email'} = join(',', grep { $approved{$_} } @addresses) if $unapproved;
        &save_scheduled_backup($b); # Preserve approved operator recipients, error policy and enabled schedule.
    }
    for my $d (&list_domains()) {
        &lock_domain($d);
        my $fresh = &get_domain($d->{'id'}, undef, 1);
        die "Domain vanished during handover" if !$fresh;
        &praho_enforce_resource_policy($fresh);
        $fresh->{'letsencrypt_email'} = 2;
        &save_domain($fresh);
        &unlock_domain($fresh);
    }
    &setup_scriptwarn_job(0);
    &foreign_require('status');
    my %allowed = map { lc($_) => 1 } @$operators;
    for my $m (&status::list_services()) {
        next if !$m->{'virtualmin'};
        # Keep only explicitly approved operator recipients; unknown custom copies cannot bypass ownership.
        $m->{'email'} = join(',', grep { $allowed{$_} } &praho_addresses($m->{'email'}));
        &status::save_service($m);
    }
}

# Virtualmin reads the account's resolved template when it creates a database, so the global value alone proves nothing.
# Effective values only: a template that inherits is safe once the default is (ADR-0075).
sub praho_database_policy_overrides {
    local *ensure_template = sub { };
    return [map { $_->{'id'} } grep { &get_template($_->{'id'})->{'mysql_chgrp'} } &list_templates()];
}

sub praho_database_policy {
    return { overrides => &praho_database_policy_overrides() };
}

sub praho_repair_database_policy {
    local *ensure_template = sub { };
    &save_module_config_keys({mysql_chgrp=>0});
    $config{'mysql_chgrp'} = 0;
    undef(@list_templates_cache);
    my @repaired;
    for my $t (&list_templates()) {
        next if !&get_template($t->{'id'})->{'mysql_chgrp'};
        $t->{'mysql_chgrp'} = 0;
        &save_template($t);
        push @repaired, $t->{'id'};
    }
    undef(@list_templates_cache);
    my $remaining = &praho_database_policy_overrides();
    die 'A Virtualmin template still charges databases to their account: '.join(', ', @$remaining)."\n" if @$remaining;
    return { overrides => $remaining, repaired => \@repaired };
}

unless (caller) {
    die "Root notification policy operation required" if $> != 0 || @ARGV != 1 || $ARGV[0] !~ /\A(?:inspect|apply|resource|reserve_probe|database_policy|database_policy_repair)\z/;
    $main::no_acl_check = 1;
    $ENV{'WEBMIN_CONFIG'} = '/etc/webmin';
    $ENV{'WEBMIN_VAR'} = '/var/webmin';
    $0 = '/usr/share/webmin/virtual-server/praho-notification-policy.pl';
    chdir('/usr/share/webmin/virtual-server') or die "Missing native Virtualmin";
    require './virtual-server-lib.pl';
    if ($ARGV[0] =~ /\Adatabase_policy/) {
        print JSON::PP->new->canonical->encode($ARGV[0] eq 'database_policy' ? &praho_database_policy() : &praho_repair_database_policy());
        exit(0);
    }
    if ($ARGV[0] eq 'reserve_probe') {
        print JSON::PP->new->canonical->encode(&praho_reserve_probe_identity());
        exit(0);
    }
    if ($ARGV[0] eq 'apply') {
        my $raw = do { local $/; <STDIN> };
        die 'Oversized notification policy request' if length($raw) > 65536;
        my $request = length($raw) ? JSON::PP->new->decode($raw) : {};
        my $extra = $request->{'operator_emails'} || [];
        die 'Invalid operator recipient authority' if ref($extra) ne 'ARRAY' || @$extra > 25 || grep { ref($_) || /[\r\n\0]/ } @$extra;
        my $operators = &praho_operator_policy($request->{'replace_authority'}, $extra);
        &praho_apply_notification_policy($operators);
    }
    elsif ($ARGV[0] eq 'resource') {
        &praho_apply_resource_policy();
    }
    print JSON::PP->new->canonical->encode(&praho_notification_inventory());
}
1;
