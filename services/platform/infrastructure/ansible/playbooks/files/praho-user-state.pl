#!/usr/bin/perl
# Projection only. Native capture/fencing/restore are not dispatched at this checkpoint.
use strict;
use warnings;
use FindBin qw($RealBin);
use Fcntl qw(:mode);

sub refuse {
    print STDERR "USER_STATE_ERROR=$_[0]\n";
    exit 1;
}

refuse('root_required') unless $> == 0;
refuse('invalid_action') unless @ARGV == 1 && $ARGV[0] eq 'project';
my $protocol = "$RealBin/praho_user_state.py";
foreach my $entry ($RealBin, $protocol) {
    my @info = lstat($entry);
    refuse('unsafe_projection_helper') unless @info && $info[4] == 0 && !($info[2] & 077)
        && ($entry eq $RealBin ? S_ISDIR($info[2]) : S_ISREG($info[2]) && $info[3] == 1);
}
# Ignore caller PYTHONPATH/user site; the protocol emits no private stdin values.
exec {'/usr/bin/python3'} '/usr/bin/python3', '-I', $protocol, 'project'
    or refuse('projection_unavailable');
