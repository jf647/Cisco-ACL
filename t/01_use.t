#
# $Id: 01_use.t,v 1.2 2004/01/27 15:34:41 james Exp $
#

use strict;
use warnings;

use Test::More tests => 2;

use_ok('Cisco::ACL');
is($Cisco::ACL::VERSION, '0.10', 'check module version');

#
# EOF
