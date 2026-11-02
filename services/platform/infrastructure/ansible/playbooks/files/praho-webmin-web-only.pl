#!/usr/bin/perl
# Apply approved administrator restrictions through Webmin's native account API.
use strict;
use warnings;
our ($no_acl_check, %gconfig);
$no_acl_check = 1;
$ENV{'WEBMIN_CONFIG'} = '/etc/webmin';
$ENV{'WEBMIN_VAR'} = '/var/webmin';
chdir('/usr/share/webmin') or die "Webmin is unavailable\n";
$0 = '/usr/share/webmin/praho-web-only';
require './web-lib.pl';
&init_config();
&foreign_require('acl', 'acl-lib.pl');
my $api = shift(@ARGV) // '';
$api =~ /^[a-z][a-z0-9_-]{2,31}$/ && $api ne 'root' or die "Dedicated API principal required\n";
my @networks = @ARGV;
@networks or die "Administrative networks required\n";
foreach my $net (@networks) {
    ($net =~ /^\d{1,3}(?:\.\d{1,3}){3}\/(\d{1,2})$/ && $1 >= 1 && $1 <= 32) ||
    ($net =~ /^[0-9a-f:]+\/(\d{1,3})$/ && $1 >= 1 && $1 <= 128) or die "Invalid network\n";
}
&acl::get_user($api) or die "Enroll and prove the dedicated API principal first\n";
my $changed = 0;
foreach my $user (&acl::list_users()) {
    my $wanted = $user->{'name'} eq $api ? join(' ', @networks) : '127.0.0.1/32';
    next if ($user->{'allow'} // '') eq $wanted && ($user->{'deny'} // '') eq '';
    $user->{'allow'} = $wanted;
    $user->{'deny'} = '';
    &acl::modify_user($user->{'name'}, $user);
    my %miniserv;
    &get_miniserv_config(\%miniserv);
    &acl::delete_session_user(\%miniserv, $user->{'name'}) if $user->{'name'} ne $api;
    $changed++;
}
my %miniserv;
&get_miniserv_config(\%miniserv);
if (($miniserv{'listen'} // '') ne '') {
    $miniserv{'listen'} = '';
    &put_miniserv_config(\%miniserv);
    $changed++;
}
&reload_miniserv() if $changed;
print "PRAHO_WEBMIN_CHANGED=$changed\n";
