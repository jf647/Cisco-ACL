#
# $Id$
#

use strict;
use warnings;

BEGIN {
    use Test::More;
    use Test::Exception;
    our $tests = 41;
    eval "use Test::NoWarnings";
    $tests++ unless( $@ );
    plan tests => $tests;
}

my $package = 'Cisco::ACL';

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
    acls
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
    if( UNIVERSAL::can($acl, "${accessor}_push") ) {
        is_deeply scalar $acl->$accessor, [ $value ], "$accessor is [ $value ]";
    }
    else {
        is $acl->$accessor, $value, "$accessor is $value";
    }
}

# make sure context return of lists works
is( ref scalar $acl->acls, 'ARRAY', 'call ->acls in scalar context');

# make sure that we can pass a single value for an attribute that is a C::MM
# list to the constructor
lives_ok {
    $acl = $package->new( dst_port => 21937 );
} 'pass single value for list attr to constructor';
isa_ok $acl, 'Cisco::ACL';
is $acl->dst_port_count, 1, 'count of dst_port list is 1';
is_deeply scalar $acl->dst_port, [ 21937 ], 'one value stored in dst_port list';

# make sure that we can pass an empty listref for an attribute
lives_ok {
    $acl = $package->new( dst_port => [] );
} 'pass single value for list attr to constructor';
isa_ok $acl, 'Cisco::ACL';
is $acl->dst_port_count, 0, 'count of dst_port list is 0';
is_deeply scalar $acl->dst_port, [ ], 'no values stored in dst_port list';

#
# EOF
