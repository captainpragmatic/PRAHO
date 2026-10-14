#!/usr/bin/perl
# Create or update the Webmin user PRAHO calls Virtualmin's remote API with.
# Usage: praho-webmin-api-user <login> <network>...   (password on stdin)
#
# The user is a Virtualmin master administrator limited to the virtual-server
# Webmin module, and may log in only from the given networks (Webmin's
# per-user IP allow list, enforced for remote.cgi and the login form alike).
# See ADR-0060.
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

# Networks arrive as Platform normalised them: an address with an explicit
# prefix (203.0.113.7/32, 2001:db8::/48). A bare address would be read by
# Webmin as a partial match (203.0.113.0 matches 203.0.113.x), so only
# prefixed forms are accepted, and never a catch-all /0.
my @networks = @ARGV;
@networks || die "no allowed networks given; refusing to create an unrestricted API user\n";
foreach my $net (@networks) {
	($net =~ /^\d{1,3}(?:\.\d{1,3}){3}\/(\d{1,2})$/ && $1 >= 1 && $1 <= 32) ||
	($net =~ /^[0-9a-f:]+\/(\d{1,3})$/ && $1 >= 1 && $1 <= 128) ||
		die "invalid allowed network '$net'\n";
	}

my $pass = <STDIN>;
defined($pass) || die "no password on stdin\n";
chomp($pass);
length($pass) >= 16 || die "password too short\n";

my $enc = &acl::encrypt_password($pass);
my $user = &acl::get_user($name);
my $state;
if (!$user) {
	$user = { 'name' => $name };
	$state = 'created';
	}
else {
	$state = 'updated';
	}
$user->{'pass'} = $enc;
$user->{'modules'} = [ 'virtual-server' ];
$user->{'allow'} = join(' ', @networks);
$user->{'deny'} = '';
if ($state eq 'created') {
	&acl::create_user($user);
	}
else {
	&acl::modify_user($name, $user);
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
print "PRAHO_API_USER=$state allow=", join(',', @networks), "\n";
