#
# $Id$
#

use strict;
use warnings;

BEGIN {
    use Test::More;
    our $tests = 2;
    eval "use Test::NoWarnings";
    $tests++ unless( $@ );
    plan tests => $tests;
}

use_ok('Cisco::ACL');
is($Cisco::ACL::VERSION, '0.12', 'check module version');

#
# EOF
