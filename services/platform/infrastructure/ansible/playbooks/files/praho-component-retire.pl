#!/usr/bin/perl
# Retire only the exact native website and PHP pool; retain mail/DNS/Unix/TLS files.
use strict;
use warnings;
use JSON::PP qw(decode_json encode_json);
use Digest::SHA qw(sha256_hex);

die "Source component retirement requires root\n" unless $> == 0;
my $input = '';
while (length($input) <= 65536) {
    my $count = read(STDIN, my $part, 65537 - length($input));
    die "Source retirement input unreadable\n" unless defined($count);
    last unless $count;
    $input .= $part;
}
die "Source retirement input too large\n" if length($input) > 65536;
my $request = eval { decode_json($input) };
die "Invalid source retirement input\n" unless ref($request) eq 'HASH';
my $action = $request->{'action'} // '';
die "Unsupported source retirement action\n" unless $action =~ /\A(?:inspect|retire|verify|sql_metadata)\z/;
foreach my $name (qw(domain_id domain owner home web_sha256 uid)) {
    die "Invalid source retirement identity\n" unless defined($request->{$name}) && !ref($request->{$name});
}
die "Invalid source domain\n" unless $request->{'domain_id'} =~ /\A[0-9]{1,30}\z/
    && $request->{'domain'} =~ /\A[A-Za-z0-9][A-Za-z0-9.-]{0,252}\z/
    && $request->{'owner'} =~ /\A[A-Za-z0-9][A-Za-z0-9_.\@-]{0,79}\z/
    && $request->{'home'} eq '/home/'.$request->{'owner'}
    && $request->{'uid'} =~ /\A[0-9]+\z/ && $request->{'uid'} > 0
    && $request->{'web_sha256'} =~ /\A[0-9a-f]{64}\z/;

sub protected_contents {
    my ($path, $maximum) = @_;
    my @info = lstat($path);
    die "Unqualified native source file\n" unless @info && -f _ && !-l _ && $info[4] == 0
        && !($info[2] & 0022) && $info[7] <= $maximum;
    open(my $stream, '<', $path) or die "Native source file unreadable\n";
    local $/;
    my $data = <$stream>;
    close($stream) or die "Native source file unreadable\n";
    return $data;
}
my $php_library = '/usr/share/webmin/virtual-server/php-lib.pl';
die "Qualify the installed PHP callbacks before source retirement\n" unless
    sha256_hex(protected_contents($php_library, 4 * 1024 * 1024)) eq
    'c7275c5b14897bc9311526ac86a42e8a34aa31139c38d44137c693c0f0536568';

package virtual_server;
$main::no_acl_check = 1;
$ENV{'WEBMIN_CONFIG'} = '/etc/webmin';
$ENV{'WEBMIN_VAR'} = '/var/webmin';
$0 = '/usr/share/webmin/virtual-server/modify-domain.pl';
chdir('/usr/share/webmin/virtual-server') or die "Native Virtualmin unavailable\n";
require './virtual-server-lib.pl';
&lock_domain($request->{'domain_id'});
my $domain = &get_domain($request->{'domain_id'});
die "The original source domain is absent\n" unless $domain;
die "The original source owner or Unix identity changed\n" unless
    $domain->{'id'} eq $request->{'domain_id'} && $domain->{'dom'} eq $request->{'domain'}
    && $domain->{'user'} eq $request->{'owner'} && $domain->{'home'} eq $request->{'home'}
    && $domain->{'uid'} == $request->{'uid'};
my @unix = getpwnam($domain->{'user'});
die "The retained Unix owner changed\n" unless @unix && $unix[2] == $request->{'uid'} && $unix[7] eq $domain->{'home'};
my $file = '/etc/apache2/sites-available/'.$domain->{'dom'}.'.conf';
my @units;

if ($action eq 'sql_metadata') {
    my $selected = $request->{'selected_databases'};
    die "Invalid selected source database metadata\n" unless ref($selected) eq 'ARRAY' && @$selected <= 100;
    my %selected;
    foreach my $name (@$selected) {
        die "Invalid selected source database\n" unless defined($name) && !ref($name) && $name =~ /\A[A-Za-z0-9_]{1,64}\z/ && !$selected{$name}++;
    }
    my @owned = split(/\s+/, $domain->{'db_mysql'} // '');
    my %owned = map { $_ => 1 } @owned;
    die "Selected source database ownership changed\n" if grep { !$owned{$_} } keys %selected;
    my @remaining = grep { !$selected{$_} } @owned;
    $domain->{'db_mysql'} = join(' ', @remaining);
    $domain->{'mysql'} = @remaining ? 1 : 0;
    &save_domain($domain);
}
else {
    &require_apache();
    &obtain_lock_web($domain);
    my @pools;
    foreach my $configuration (&list_php_fpm_configs()) {
        my $pool = $configuration->{'dir'}.'/'.$domain->{'id'}.'.conf';
        next unless -e $pool || -l $pool;
        die "Unqualified source PHP pool path\n" unless $pool =~ m!\A/etc/php/[0-9]+(?:\.[0-9]+)?/fpm/pool\.d/\Q$domain->{'id'}\E\.conf\z!;
        my $unit = $configuration->{'init'} // '';
        die "Prepare a qualified graceful PHP reload before retirement\n" unless $unit =~ /\Aphp[0-9]+(?:\.[0-9]+)?-fpm\z/;
        push(@pools, { 'path' => $pool, 'sha256' => Digest::SHA::sha256_hex(main::protected_contents($pool, 262144)), 'unit' => $unit });
    }
    if ($action eq 'verify') {
        die "The native source website or PHP pool remains\n" unless !$domain->{'web'} && !$domain->{'ssl'} && !@pools;
        if (-e $file || -l $file) {
            main::protected_contents($file, 262144);
            my $configuration = [ &apache::get_config_file($file) ];
            die "Native website definitions remain after retirement\n" if &apache::find_directive_struct('VirtualHost', $configuration);
        }
    }
    else {
        die "The source website changed before retirement\n" unless $domain->{'web'}
            && Digest::SHA::sha256_hex(main::protected_contents($file, 262144)) eq $request->{'web_sha256'};
        my $expected = $request->{'pool_digests'};
        die "Invalid source PHP pool evidence\n" unless ref($expected) eq 'ARRAY' && @$expected == @pools;
        my %expected = map { $_->{'path'} => $_->{'sha256'} } @$expected;
        die "The reviewed source PHP pool changed\n" if grep { !defined($expected{$_->{'path'}}) || $expected{$_->{'path'}} ne $_->{'sha256'} } @pools;
        my $configuration = [ &apache::get_config_file($file) ];
        my @vhosts = &apache::find_directive_struct('VirtualHost', $configuration);
        my %ports;
        foreach my $vhost (@vhosts) {
            my $name = &apache::find_directive('ServerName', $vhost->{'members'});
            my $port = $vhost->{'words'}->[0] =~ /:(\d+)\z/ ? $1 : 80;
            die "Foreign native vhost in the selected source file\n" unless lc($name // '') eq $domain->{'dom'} && ($port == 80 || $port == 443) && !$ports{$port}++;
        }
        die "The source customer HTTP vhost is absent\n" unless $ports{80};
        if ($action eq 'retire') {
            foreach my $port (443, 80) {
                next unless $ports{$port};
                &apache::flush_config_cache();
                my ($vhost, $members, $configuration) = &get_apache_virtual($domain->{'dom'}, $port, $file);
                die "The exact original native vhost changed\n" unless $vhost && $vhost->{'file'} eq $file;
                &delete_web_virtual_server($vhost, $configuration);
            }
            # The native delete_php_fpm_pool callback forces a shared service
            # restart and unlinks an inferred socket path. Remove only these
            # verified native pool files; the caller performs graceful reload
            # without a restart fallback and lets PHP-FPM retire its own sockets.
            foreach my $pool (@pools) {
                die "The source PHP pool changed during retirement\n" unless Digest::SHA::sha256_hex(main::protected_contents($pool->{'path'}, 262144)) eq $pool->{'sha256'};
                &unlink_logged($pool->{'path'});
                &unflush_file_lines($pool->{'path'});
                push(@units, $pool->{'unit'});
            }
            $domain->{'web'} = 0;
            $domain->{'ssl'} = 0;
            # Keep every certificate/key/sharing/renewal field unchanged. In
            # particular never invoke delete_ssl or delete_domain callbacks.
            &save_domain($domain);
        }
    }
    &release_lock_web($domain);
}
&unlock_domain($domain->{'id'});
my $digest = -e $file ? Digest::SHA::sha256_hex(main::protected_contents($file, 262144)) : '';
print JSON::PP::encode_json({ 'domain_id' => $domain->{'id'}, 'web_sha256' => $digest, 'php_units' => \@units });
