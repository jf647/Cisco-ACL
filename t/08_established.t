#
# $Id$
#

use strict;
use warnings;

BEGIN {
    use Test::More;
    use Test::Exception;
    our $tests = 5;
    eval "use Test::NoWarnings";
    $tests++ unless( $@ );
    plan tests => $tests;
}

my $package = 'Cisco::ACL';

use_ok($package);

my $acl;
lives_ok {
    $acl = $package->new( established => 1 );
} 'create an ACL object';
isa_ok($acl, $package);

$acl->permit(1);
$acl->dst_addr( '1.1.1.1' );
$acl->dst_port( '21937' );
$acl->protocol('tcp');

my $expected = "permit tcp any host 1.1.1.1 eq 21937 established";
my $gotback = $acl->acls->[0];
is($gotback, $expected, 'established ACL matches');

$acl->reset;

$acl->permit(1);
$acl->established(1);

$expected = "permit tcp any any established";
$gotback = $acl->acls->[0];
is($gotback, $expected, 'established ACL matches');

#
# EOF
