#
# $Id: 01_use.t,v 1.3 2004/01/29 01:18:11 james Exp $
#

use strict;
use warnings;

use Test::More tests => 2;

use_ok('Cisco::ACL');
is($Cisco::ACL::VERSION, '0.11', 'check module version');

#
# EOF
