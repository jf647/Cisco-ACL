#
# $Id$
#

use strict;
use warnings;

BEGIN {
    use Test::More;
    use Test::Exception;
    our $tests = 3;
    eval "use Test::NoWarnings";
    $tests++ unless( $@ );
    plan tests => $tests;
}

my $package = 'Cisco::ACL';

use_ok($package);

throws_ok {
    Cisco::ACL::decimal_to_bin(2**32+1);
} qr/exceeded MAXINT/, 'can\'t do decimal_to_bin on > 2**32';

throws_ok {
    Cisco::ACL::decimal_to_bin(10.5);
} qr/You have been eaten by a grue/, 'can\'t do decimal_to_bin on 10.5';

#
# EOF
