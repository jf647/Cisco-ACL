#
# $Id$
#

=head1 NAME

Net::ACL::Cisco - generate access control lists for Cisco IOS

=head1 SYNOPSIS

  use Net::ACL::Cisco;
  my $acl = Net::ACL::Cisco->new(
    permit   => 1,
    src_addr => '10.1.1.1/24',
    dst_addr => '10.1.2.1/24',
  );
  print "$_\n" for( $acl->lists );

=head1 DESCRIPTION

=cut

package Net::ACL::Cisco;

use strict;
use warnings;

our $VERSION = 0.10;

use Carp                    qw|croak|;
use Params::Validate        qw|:all|;

# set up class methods
use Class::MethodMaker(
    new_with_init => 'new',
    boolean       => 'permit',
    get_set       => [ qw|
        src_addr
        src_port
        dst_addr
        dst_port
        protocol
    |],
);

# initialize a newly constructed object
sub init
{

    my $self = shift;
    
    # validate args
    my %args = validate(@_,{
        permit   => { type     => BOOLEAN,
                      optional => 1 },
        deny     => { type     => BOOLEAN,
                      optional => 1 },
        src_addr => { type     => SCALAR|ARRAYREF,
                      optional => 1 },
        dst_addr => { type     => SCALAR|ARRAYREF,
                      optional => 1 },
        src_port => { type     => SCALAR,
                      optional => 1 },
        dst_port => { type     => SCALAR,
                      optional => 1 },
        protocol => { type     => SCALAR,
                      optional => 1 },
    });

    # permit and deny are mutually exclusive
    if( exists $args{permit} && exists $args{deny} ) {
        croak "'permit' and 'deny' are mutually exclusive";
    }
    
    # do we have allow and is it true?
    if( exists $args{permit} && $args{permit} ) {
        $self->permit(1);
    }

    # populate the object
    $self->src_addr( $args{src_addr} );
    $self->dst_addr( $args{dst_addr} );
    $self->src_port( $args{src_port} );
    $self->dst_port( $args{dst_port} );
    $self->protocol( $args{protocol} );

    return $self;

}

# generate the access lists
sub lists
{

    my $self = shift;
    my $lists = $self->_doit;
    
    return wantarray ? @{ $lists } : $lists;

}

## all code below here is from the original acl.pl
sub _doit
{

    my $self = shift;

    my @source_addr_elements = breakout_addrs($self->src_addr);
    my @destinatione_addr_elements = breakout_addrs($self->dst_addr);
    my @source_port_elements = breakout_ports($self->src_port);
    my @destination_port_elements = breakout_ports($self->dst_port);

    my @rules;
    for my $current_src_addr (@source_addr_elements) {
        for my $current_dst_addr (@destinatione_addr_elements) {
        	for my $current_src_port (@source_port_elements) {
        	    for my $current_dst_port (@destination_port_elements) {
    	        	my $rule = make_rule(
    	        	    $self->permit,
                        $self->protocol,
                        $current_src_addr,
                        $current_dst_addr,
                        $current_src_port,
                        $current_dst_port
                    );
                    # trim trailing whitespace
                    $rule =~ s/\s+$//;
                    push @rules, $rule;
                }
    	    }
    	}
    };
    
    return \@rules;

    #
    #-------------------------------------------------------------------
    #

    sub make_rule {
      
        # Return the rule as a string, withOUT a final CR.

        my($action, $protocol, $src_addr, $dst_addr, $src_port, $dst_port) = @_;

        # $src_port and $dst_port are ready to be inserted in the rule string
        # as is; the clean_input routine prepared them, including prepending
        # "eq ".  They will be "" if the port was "any".

        my ($rule_string,$src_elem,$dst_elem,$src_p_elem,$dst_p_elem);

        if ($protocol eq "both") {
        	$protocol = "ip";
        };

        $rule_string = $action ? "permit" : "deny";
        $rule_string .= " $protocol ";

        if ($src_addr =~ /\//) {
    	$src_elem = parse_cidr($src_addr);
        }
        elsif ($src_addr =~ /any/) {
    	$src_elem = "any";
        }
        else {
    	$src_elem = "host $src_addr";
        };

        if ($dst_addr =~ /\//) {
    	$dst_elem = parse_cidr($dst_addr);
        }
        elsif ($dst_addr =~ /any/) {
    	$dst_elem = "any";
        }
        else {
            $dst_elem = "host $dst_addr";
        };

        if ($src_port =~ /any/) {
    	$src_p_elem = "";
        }
        else {
    	$src_p_elem = $src_port;
        };

        if ($dst_port =~ /any/) {
    	$dst_p_elem = "";
        }
        else {
    	$dst_p_elem = $dst_port;
        };

        $rule_string .= "$src_elem $src_p_elem $dst_elem $dst_p_elem";
        $rule_string =~ s/\s+/ /g;
        return $rule_string;

    };

    #
    #-------------------------------------------------------------------
    #

    sub breakout_addrs {

        # Split on commas, return a list where every element is either a
        # single address or a single cidr specification.

        my $list = $_[0];
        if ($list =~ /any/) { return("any"); };

        my (@elements,$addr,@endpoints,@octets1,@octets2,$start,$end,$i,@unwashed_masses,
    	$number_of_endpoints,$number_of_octets,$done,$dec_start,$dec_end,@george,$remaining);

        @unwashed_masses = ref $list eq 'ARRAY' ? @{ $list } : $list;

        foreach $addr( @unwashed_masses ) {
    	if ($addr !~ /\-/) {
    	    push @elements, $addr;  # Not a range and we're returning single addresses and
                                        # cidr notation as is, so nothing to do
    	}
    	else {
    	    @endpoints = split(/\-/, $addr);
    	    $number_of_endpoints = @endpoints;
    	    if ($number_of_endpoints != 2) {
    		next;  # something is screwey; probably something like
                           # 10.10.10.10-20-30.  Silently shitcan it.
    	    };

    	    # Two cases left; x.x.x.x-y.y.y.y and x.x.x.x-y
    	    #
    	    @octets2 = split(/\./, $endpoints[1]);
    	    $number_of_octets = @octets2;
    	    if ($number_of_octets == 4) {
    		$dec_start = ip_to_decimal($endpoints[0]);
    		$dec_end = ip_to_decimal($endpoints[1]);
    		push @elements, ferment("$dec_start-$dec_end");
    	    }
    	    else {
    		@octets1 = split(/\./, $endpoints[0]);
    		my $newend = "$octets1[0].$octets1[1].$octets1[2].$octets2[0]";
    		$dec_start = ip_to_decimal($endpoints[0]);
    		$dec_end = ip_to_decimal($newend);
                    push @elements, ferment("$dec_start-$dec_end");
    	    }
    	}
        }
        return(@elements);
    }

    #
    #-------------------------------------------------------------------
    #

    sub breakout_ports {
        my $list = $_[0];
        $list =~ s/\///g;   # Told you I'd deal with it later...
        my (@items,$tidbit,@endpoints,$start,$end,$i,$number_of_endpoints,@elements);
        @items = split(/,/, $list);
        foreach $tidbit (@items) {
    	if ($tidbit =~ /\-/) {
    	    @endpoints = split(/\-/, $tidbit);

    	    $number_of_endpoints = @endpoints;
    	    if ($number_of_endpoints != 2) {
    		next;
    	    };

    	    $start = $endpoints[0];
    	    $end = $endpoints[1];

    	    if ($start >= $end) {
    		next;
    	    };

    	    for ($i = $start; $i <= $end; $i++) {
    		push @elements, "eq $i";
    	    };
    	}
            else {
    	    push @elements, "eq $tidbit";
    	}
        };
        return(@elements);
    };

    #
    #-------------------------------------------------------------------
    #

    sub parse_cidr {
        my $bob = $_[0];
        my ($address, $block, $start, $end, $mask, $rev_mask);
        ($address, $block) = split(/\//, $bob);
        ($start, $end) = ip_to_endpoints($address, $block);
        $mask = find_mask($block);
        my $bin_mask = ip_to_bin($mask);
        my @bits = split(//, $bin_mask);
        foreach my $toggle_bait (@bits) {
    	if ($toggle_bait eq "1") {
    	    $toggle_bait = "0";
    	}
    	else {
    	    $toggle_bait = "1";
    	};
        };
        my $inv_bin = join "",@bits;
        my $inv_mask = bin_to_ip($inv_bin);
        return "$start $inv_mask ";
    }

    #
    #-------------------------------------------------------------------
    #

    sub ferment {

        # Ferment = "cidr-ize" the address range (ha ha, ok, I'll keep
        # my day job.)  Take the range given as xxxx-yyyy (it's decimal!!)
        # and find the most concise way to express it in cidr notation.

        # Return: The list of elements, or "" if the range given was ""

        # Arguments: the range, the list of elements to add to.

        my $range = shift(@_);
        my @list_to_date = @_;
        my ($start,$end,$difference,$i,$got_it,@working_list,
    	$trial_start,$trial_end,$dotted_start,$block_found,$remaining_range);

        if ($range eq "") { return(@list_to_date) };   # an end condition

        ($start, $end) = split(/\-/, $range);
        $difference = $end - $start;

        if ($difference == 0) {

    	# The range is one address (i.e. start and end are the same);
    	# return it in dotted notation and we're at another end condition.

    	push @list_to_date, decimal_to_ip($start);
    	return(@list_to_date);
        };

        $got_it = 0;
        for ($i = 1; $i < 31; $i++) {

    	# We'll only try to put 1 block per call of this subroutine
    	if ($got_it) { last };

    	# Using the cidr size for this loop iteration, calculate what
    	# the block of that size would be for the start address we
    	# have, then compare that to the range we're looking for.
    	# 
    	($trial_start, $trial_end) = ip_to_endpoints(decimal_to_ip($start),$i); # dotted
    	$trial_start = ip_to_decimal($trial_start);          # now decimal
    	$trial_end = ip_to_decimal($trial_end);

    	#
    	# Ok, now these are in decimal
    	#
    	if ($trial_start == $start) {
    	    # Woo hoo, the start of the range is aligned with a cidr boundary.
    	    # Is it the right one?  We know it's the biggest possible,
    	    # but it may be too big.  If so, just move on to the next
    	    # $i (i.e. next smaller sized block) and try again.
    	    #
    	    if ($trial_end > $end) { next; };

    	    # otherwise, it's the money...
    	    #
    	    $got_it = 1;
    	    $dotted_start = decimal_to_ip($start);
    	    $block_found = "$dotted_start/$i";
    	    $start += (($trial_end - $start) + 1);
    	    #
    	    # Ok, now we've reduced the range by the amount of space
    	    # in the block we just found.  
    	    #
    	    # The extra '+1' above means that the next start point
    	    # will be one address beyond the end of the block we
    	    # just found (otherwise we'd find a few individual addresses
    	    # twice).  However, it also means that for the final block,
    	    # $start is > $end by 1.  We have to check for that before
    	    # returning the values; if we let it through we'll
    	    # spin forever...
    	    #
    	}
    	else {
    	    next;  # try the next smaller size block
    	}
        }  # for loop

        # Ok, we're done trying cidr blocks.  If we found one, return it
        # and the remaining range.  Otherwise, return 1 address and the
        # remaining range.

        if ($got_it) {
    	# We already calculated $block_found
    	$remaining_range = "$start-$end";
    	if ($start > $end) { $remaining_range = "" }
        }
        else {
    	$block_found = decimal_to_ip($start);
    	$start++;
    	$remaining_range = "$start-$end";
    	if ($start > $end) { $remaining_range = "" }
        }

        push @list_to_date, $block_found;
        return(ferment($remaining_range,@list_to_date));

    };

    #
    #-------------------------------------------------------------------
    #

    sub ip_to_endpoints {
        #
        # Various of these routings use strings for bit masks where
        # it would undoubtedly be much more efficient to use real binary
        # data, but... it's fast enough, and this was easier.  :)
        #
        my($address,$cidr,$zeros,$ones,$bin_address);
        $address = $_[0];
        $bin_address = ip_to_bin($address);
        $cidr = $_[1];
        $zeros = "00000000000000000000000000000000";
        $ones  = "11111111111111111111111111111111";
        for(my $i=0; $i<=($cidr-1); $i++) {
    	substr($zeros,$i,1) = substr($bin_address,$i,1);
        substr($ones,$i,1) = substr($bin_address,$i,1)
        };
        return(bin_to_ip($zeros), bin_to_ip($ones));
    };

    ###########################################################################

    sub find_mask {
        my($cidr,$bin,$i);
        $cidr = $_[0];
        $bin = "00000000000000000000000000000000";
        for ($i=0; $i<=31; $i++) {
    	if ($i <= ($cidr-1)) {
    	    substr($bin,$i,1) = "1"
    	    }
        }
        my $mask = bin_to_ip($bin);
        return($mask);
    };

    ############################################################################

    sub ip_to_decimal {
        my($address, $i, $a, $b, $c, $d);
        $address = shift(@_);
        ($a, $b, $c, $d) = split(/\./, $address);
        $i = (256**3)*$a + (256**2)*$b + 256*$c + $d ;
        return($i);
    };

    ############################################################################
    #
    # Ok, so, it's a hack... sue me.  :)
    #

    sub decimal_to_ip {
        return bin_to_ip(decimal_to_bin($_[0]));
    };

    ############################################################################

    sub decimal_to_bin {
        my($decimal,@bits,$i,$bin_string);
        $decimal = $_[0];
        @bits = "";
        for ($i=0;$i<=31;$i++) {
    	$bits[$i] = "0";
        };
        if ($decimal >= 2**32) {
    	die "Error: exceeded MAXINT.\n\n";
        };
        
        for ($i=0; $i<=31; $i++) {
    	if ($decimal >= 2**(31 - $i)) {
    	    $bits[$i] = "1";
    	    $decimal -= 2**(31 - $i);
    	}
        };

        $bin_string = "";
        $bin_string = join('',@bits);

        if ($decimal != 0) {
    	print "\nWARNING!!\nDANGER, WILL ROBINSON!!\nTHERE IS A GRUE NEARBY!!\n\n";
    	print "A really simple check of decimal-to binary conversion choked!\n\n";
    	print "Decimal value (expected zero): $decimal\nBinary result: $bin_string\n";
    	die "\nSuddenly the lights go out...\n\nYou hear a grumbling sound...\n\nYou have been eaten by a grue.\n\n";
        };
        return($bin_string);
    };

    ##############################################################

    sub bin_to_ip {
        my($bin,$ip,@octets,$binoct1,$binoct2,$binoct3,$binoct4,$address);
        $bin = $_[0];
        @octets = "";
        $binoct1 = substr($bin,0,8);
        $binoct2 = substr($bin,8,8);
        $binoct3 = substr($bin,16,8);
        $binoct4 = substr($bin,24,8);
        $octets[0] = bin_to_decimal($binoct1);
        $octets[1] = bin_to_decimal($binoct2);
        $octets[2] = bin_to_decimal($binoct3);
        $octets[3] = bin_to_decimal($binoct4);
        $address = join('.',@octets);
        return($address);
    };

    ##############################################################
    # ip_to_bin
    #

    sub ip_to_bin {
        my($ipaddr,$x,$y);
        $ipaddr = $_[0];
        $x = ip_to_decimal($ipaddr);
        $y = decimal_to_bin($x);
        return($y);
    };

    ############################################################################

    sub bin_to_decimal {

        # Assume 8-bit unsigned integer max
        # This is only meant to be called from bin_to_ip

        my($binary,$decimal,$i,$power,$bit,$total);
        $binary = $_[0];
        $total = 0;
        for ($i=0; $i<=7; $i++) {
    	$power = 7 - $i;
    	$bit = substr($binary,$i,1);
    	if ($bit) {
    	    $total += 2**$power;
    	}
        };
        return($total);
    };

}

# keep require happy
1;


__END__


=head1 CONSTRUCTOR

To construct a Net::ACL::Cisco object, call the B<new> method.  The following
optional arguments can be passed as a hash of key/val pairs:

=over 4

=item * permit

A boolean value indicating that this ACL is a permit ACL. If not provided,
defaults to true.

=item * deny

The opposite of permit.  The value must be true in Perl's eyes.

=item * src_addr

The source address in CIDR format.  May be a single scalar or an arrayref of
addresses.

=item * src_port

The source port.  If not provided, defaults to 'any'.

=item * dst_addr

The destination address in CIDR format.  May be a single scalar or an
arrayref of addresses.

=item * dst_port

The destination port.  If not provided, defaults to 'any'.

=item * protocol

The protocol.  If not provided, defaults to 'tcp'.

=back

=head1 ACCESSORS

=head1 METHODS

=head1 EXAMPLES

=head1 BUGS

=head1 TODO

The initial version of this module is pretty much an OO wrapper around
Chris De Young's original code.  Future plans include (hopefully in order
of implementation):

=over 4

=item * use CPAN modules where possible

The original code did all it's own CGI processing - I'd like to move to
CGI.pm instead.

=item * refactor mercilessly

I want to build up the test suite to a fair size and then start looking
for places to make things cleaner, faster, smaller, etc.

=item * support Cisco's port range syntax

This is a TODO that Chris noted when he gave me the source.

=item * make sure that everything produced is up-to-date with IOS

It's been a while since I've had to play with a Cisco, so what I know
might not be totally up to date with the latest software revs.

=item * support the use of Net::ACL::Match objects

I'd like to be able to pass Net::ACL::Match (written by Martin Lorensen)
objects into the constructor and generate access-list output based upon
their properties.

=back

=head1 AUTHOR

James FitzGibbon, E<lt>jfitz@CPAN.orgE<gt>

=head1 ORIGINAL AUTHOR

The code in this module started life as acl.pl, a CGI script written
by Chris De Young (chd AT chud DOT net).  He placed it in the public
domain on Dec 6th, 2002.  Any mistakes in this module are probably mine.

=head1 COPYRIGHT

This module is free software.  You may use and/or modify it under the
same terms as perl itself.

=cut

#
# EOF
