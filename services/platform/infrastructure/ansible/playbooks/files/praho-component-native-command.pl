#!/usr/bin/perl
# Execute a fixed native target callback with private arguments on stdin. In
# particular, placeholder passwords must not enter the operating system argv.
use strict;
use warnings;
use JSON::PP qw(decode_json);

die "Native component commands require root\n" unless $> == 0;
my $input = '';
while (length($input) <= 65536) {
    my $count = read(STDIN, my $part, 65537 - length($input));
    die "Native component input is unreadable\n" unless defined($count);
    last unless $count;
    $input .= $part;
}
die "Native component command exceeds its bound\n" unless length($input) <= 65536;
my $request = eval { decode_json($input) };
die "Invalid native component command\n" unless ref($request) eq 'HASH';
my $program = $request->{'program'};
my %allowed = map { $_ => 1 } qw(create-domain disable-domain restore-domain enable-domain delete-domain list-domains);
die "Unqualified native component command\n" unless defined($program) && $allowed{$program};
my $arguments = $request->{'arguments'};
die "Invalid native component arguments\n" unless ref($arguments) eq 'ARRAY' && @$arguments <= 100;
foreach my $argument (@$arguments) {
    die "Invalid native component argument\n" unless defined($argument) && !ref($argument)
        && length($argument) <= 4096 && $argument !~ /[\x00\r\n]/;
}

package virtual_server;
$main::no_acl_check = 1;
$ENV{'WEBMIN_CONFIG'} = '/etc/webmin';
$ENV{'WEBMIN_VAR'} = '/var/webmin';
chdir('/usr/share/webmin/virtual-server') or die "Native Virtualmin callbacks are unavailable\n";
$0 = '/usr/share/webmin/virtual-server/'.$program.'.pl';
@ARGV = @$arguments;
# This is the installed native CLI implementation, with its original locking,
# validation and exit status. Perl @ARGV is private process memory, not OS argv.
die "Native component callback is unavailable\n" unless -f $0 && -r $0;
do $0;
# Native CLI programs use exit(1) for failure. Successful delete-domain ends
# with virtualmin_api_log(), which legitimately returns undef. The caller must
# independently verify each action's native postcondition as well as this status.
die "Native component callback failed\n" if $@;
