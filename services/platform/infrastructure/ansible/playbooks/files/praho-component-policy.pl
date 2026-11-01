#!/usr/bin/perl
# Current web/Unix policy only. Independent component SQL locks never rewrite credentials.
package virtual_server;
use strict;
use warnings;
use JSON::PP qw(decode_json encode_json);
our ($first_print, $second_print, $indent_print, $outdent_print);
die "Component policy requires root" unless $> == 0;
my $encoded; { local $/; $encoded = <STDIN>; }
die "Oversized component policy request" unless defined($encoded) && length($encoded) <= 4096;
my $p = decode_json($encoded);
die "Invalid native policy identity" unless $p->{'domain_id'} =~ /^[0-9]{1,30}$/ &&
    $p->{'domain'} =~ /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/ &&
    $p->{'owner'} =~ /^[A-Za-z_][A-Za-z0-9_-]{0,31}$/ &&
    JSON::PP::is_bool($p->{'enabled'});
$main::no_acl_check++;
$ENV{'WEBMIN_CONFIG'}='/etc/webmin'; $ENV{'WEBMIN_VAR'}='/var/webmin';
$0='/usr/share/webmin/virtual-server/enable-domain.pl';
chdir('/usr/share/webmin/virtual-server') or die "Native module unavailable";
require './virtual-server-lib.pl';
$first_print=$second_print=$indent_print=$outdent_print=sub {};
&lock_domain($p->{'domain_id'});
my $d=&get_domain($p->{'domain_id'}, undef, 1);
die "Native component policy owner changed" unless $d && $d->{'dom'} eq $p->{'domain'} &&
    $d->{'user'} eq $p->{'owner'} && !$d->{'parent'} && !$d->{'alias'} &&
    $d->{'uid'} eq $p->{'uid'} && $d->{'gid'} eq $p->{'gid'} &&
    $d->{'home'} eq '/home/'.$p->{'owner'};
my $error;
if ($p->{'enabled'}) {
    # Initial held restoration may include mysql in disabled. Its independent
    # component SQL journal owns suspension; no native password callback runs.
    my @disabled=grep { $_ ne 'mysql' } split(/,/, $d->{'disabled'} || '');
    if (join(',', @disabled) ne ($d->{'disabled'} || '')) {
        $d->{'disabled'}=join(',', @disabled);
        &save_domain($d);
    }
    $error=&enable_virtual_server($d) if @disabled;
} else {
    $error=&disable_virtual_server($d, 'manual', 'Current component hosting policy', ['unix','web','ssl']);
}
die "Native component policy callback failed" if $error;
&unlock_domain($p->{'domain_id'});
&run_post_actions();
$d=&get_domain($p->{'domain_id'}, undef, 1);
die "Native component policy did not converge" if $p->{'enabled'} ? $d->{'disabled'} : !$d->{'disabled'};
print encode_json({'enabled'=>$p->{'enabled'}, 'domain_id'=>$p->{'domain_id'}});
