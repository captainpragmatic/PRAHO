#!/usr/bin/perl
# Create or update the Webmin user PRAHO calls Virtualmin's remote API with.
# Usage: praho-webmin-api-user <login>   (the password is read from stdin)
use strict;
use warnings;

our ($no_acl_check, %gconfig);
$no_acl_check = 1;
$ENV{'WEBMIN_CONFIG'} ||= '/etc/webmin';
$ENV{'WEBMIN_VAR'} ||= '/var/webmin';
chdir('/usr/share/webmin') || die "no /usr/share/webmin: $!\n";
# init_config() derives the module from $0 and refuses paths outside the
# Webmin root; run as a top-level (module-less) Webmin script.
$0 = '/usr/share/webmin/praho-webmin-api-user';
require './web-lib.pl';
&init_config();
&foreign_require('acl', 'acl-lib.pl');

my $name = shift(@ARGV) // '';
$name =~ /^[a-z][a-z0-9_-]{2,31}$/ || die "invalid login '$name'\n";
$name eq 'root' && die "refusing to manage root\n";
my $pass = <STDIN>;
defined($pass) || die "no password on stdin\n";
chomp($pass);
length($pass) >= 16 || die "password too short\n";

my $enc = &acl::encrypt_password($pass);
my $user = &acl::get_user($name);
my $state;
if ($user) {
	$user->{'pass'} = $enc;
	$user->{'modules'} = [ 'virtual-server' ];
	&acl::modify_user($name, $user);
	$state = 'updated';
	}
else {
	&acl::create_user({ 'name' => $name, 'pass' => $enc,
			    'modules' => [ 'virtual-server' ] });
	$state = 'created';
	}

# Virtualmin's remote API runs most programs only for its master
# administrator: a virtual-server ACL without noconfig. Start from the
# module's shipped default ACL.
my %acl;
&read_file('/usr/share/webmin/virtual-server/defaultacl', \%acl) ||
	die "cannot read the virtual-server default ACL\n";
$acl{'noconfig'} = 0;
&save_module_acl(\%acl, $name, 'virtual-server');
&reload_miniserv();
print "PRAHO_API_USER=$state\n";
