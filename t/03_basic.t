#
# $Id$
#

use strict;
use warnings;

use Test::More 'no_plan';
use Test::Exception;

my $package = 'Net::ACL::Cisco';

use_ok($package);

# check for invalid use of the constructor
throws_ok {
    $package->new( foo => 'bar' );
} qr/but was not listed/, 'construct with invalid arguments';

throws_ok {
    $package->new( permit => [] );
} qr/was an 'arrayref'/, 'construct with wrongly typed arguments';

throws_ok {
    $package->new( permit => 1, deny => 1 );
} qr/'permit' and 'deny' are mutually exclusive/,
'use permit and deny together';

# now construct a real object
my $acl;
lives_ok {
    $acl = $package->new;
} 'create an ACL object';
isa_ok($acl, $package);

# check that all the methods are there
my @methods = qw|
    clear_dst_addr
    clear_dst_port
    clear_permit
    clear_src_addr
    clear_src_port
    clear_protocol
    dst_addr
    dst_port
    init
    new
    permit
    protocol
    set_permit
    src_addr
    src_port
    lists
|;
for( @methods ) {
    can_ok($acl, $_);
}

# test out the accessors
my %accessor_tests = (
    src_addr => '10.1.1.1',
    src_port => 12345,
    dst_addr => '10.1.2.1',
    dst_port => 45678,
    protocol => 'udp',
);
while( my($accessor, $value) = each %accessor_tests ) {
    lives_ok {
        $acl->$accessor($value);
    } "set $accessor";
    is($acl->$accessor, $value);
}

# make sure context return of lists works
is( ref scalar $acl->lists, 'ARRAY', 'call ->lists in scalar context');

#
# EOF
