#!/usr/bin/perl
#

# Cisco access-list generator, by Chris De Young
# chd@chud.net, chd@arizona.edu

# 06-DEC-2002 - This code is released into the public domain.  It may
# be used, copied, modified, or incorporated into other products
# without restriction.  It is provided as is, without warranty of any
# kind or for any purpose.  There are doubtless many things in here
# that would make a real perl programmer cringe; anyone who wishes to
# do so should feel free to clean up the many hacks and kludges found
# herein.  :)

print "Content-type: text/html\n\n";

&collect_input();

# Variables are: permit_or_deny, src_addr, dst_addr, src_port,
# dst_port 
# Note that the addresses and ports may be "any" or a range or list of
# ranges.

$source_addr = &clean_input($form_data{src_addr});
$destination_addr = &clean_input($form_data{dst_addr});
$source_port = &clean_input($form_data{src_port});
$destination_port =  &clean_input($form_data{dst_port});

# Cisco syntax doesn't accomodate arbitrary ranges of addresses, so
# each element that we care about here will be either a single address
# or a cidr block.  Then we'll build four lists, one for each element,
# and spit out one rule for each possible combination of them.

# It would be nice if we could catch it when the user specifies a
# large range of addresses in list format and spit out the cidr block
# version of the syntax... but we'll tackle that later.

# Also to do: Accomodate ranges of ports, e.g. "1000-2000".

@source_addr_elements = &breakout_addrs($source_addr);
@destinatione_addr_elements = &breakout_addrs($destination_addr);
@source_port_elements = &breakout_ports($source_port);
@destination_port_elements = &breakout_ports($destination_port);

print "<pre>\n\n";

foreach $current_src_addr (@source_addr_elements) {
    foreach $current_dst_addr (@destinatione_addr_elements) {
	foreach $current_src_port (@source_port_elements) {
	    foreach $current_dst_port (@destination_port_elements) {
		$rule = &make_rule($form_data{permit_or_deny},
                                   $form_data{protocol},
                                   $current_src_addr,
                                   $current_dst_addr,
                                   $current_src_port,
                                   $current_dst_port);
		print "$rule\n";
	    }
	}
    }
};

print "\n\n</pre>\n\n";

exit;

#
#-------------------------------------------------------------------
#

sub collect_input {
    local($data, $item, $name, $value);
    $data = <STDIN>;
    @fields = split(/&/, $data);
    foreach $item (@fields) {
	($name, $value) = split(/=/, $item);
	$name = &unescape($name);
	$value = &unescape($value);
	$form_data{$name} = $value;
	#
	# No carriage returns anywhere
	#
	$form_data{$name} =~ s/\n//;
    };

# test values for easier debugging only;
# comment this out for CGI use.
#
#    $form_data{protocol} = "tcp";
#    $form_data{permit_or_deny} = "deny";
#    $form_data{src_addr} = "80.8.210.0-80.8.253.255";
#    $form_data{dst_addr} = "any";
#    $form_data{src_port} = "any";
#    $form_data{dst_port} = "any";

};

#
#-------------------------------------------------------------------
#

sub unescape {
    local($s) = $_[0];
    local($pos, $ascii);
    #
    # replace + signs with spaces
    #
    $s =~ s/\+/ /g;
    #
    # find and replace %nn escaped characters
    #
    $pos = 0;
    while (($pos = index($s, "%", $pos)) != -1) {
	$ascii = hex(substr($s, $pos+1, 2));
	substr($s, $pos, 3) = pack("c", $ascii)
	};
    $s;
};

#
#-------------------------------------------------------------------
#

sub make_rule {
  
    # Return the rule as a string, withOUT a final CR.

    my $action = shift(@_);
    my $protocol = shift(@_);
    my $src_addr = shift(@_);
    my $dst_addr = shift(@_);
    my $src_port = shift(@_);
    my $dst_port = shift(@_);

    # $src_port and $dst_port are ready to be inserted in the rule string
    # as is; the clean_input routine prepared them, including prepending
    # "eq ".  They will be "" if the port was "any".

    my ($rule_string,$src_elem,$dst_elem,$src_p_elem,$dst_p_elem);

    if ($protocol eq "both") {
	$protocol = "ip";
    };

    $rule_string = "$action $protocol ";

    if ($src_addr =~ /\//) {
	$src_elem = &parse_cidr($src_addr);
    }
    elsif ($src_addr =~ /any/) {
	$src_elem = "any";
    }
    else {
	$src_elem = "host $src_addr";
    };

    if ($dst_addr =~ /\//) {
	$dst_elem = &parse_cidr($dst_addr);
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

sub clean_input {

    # Just remove any illegal junk from the input list, that's all.  We
    # have to accomodate both address and port lists, so it's possible for
    # someone to sneak a / into the port list... I'll deal with that
    # later...

    my $list = $_[0];
    $list =~ s/\s+//g;    # remove any spaces

    if ($list =~ /any/) { # if it includes "any" then the rest of the list is irrelevant
	$list = "any";
    }
    else {
	$list =~ s/[^\d\.\-\,\/]//g;
    };
    if ($list eq "") {
	$list = "any";
    };
    return($list);
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

    undef @elements;
    @unwashed_masses = split(/,/, $list);

    foreach $addr (@unwashed_masses) {
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
		$dec_start = &ip_to_decimal($endpoints[0]);
		$dec_end = &ip_to_decimal($endpoints[1]);
		push @elements, &ferment("$dec_start-$dec_end");
	    }
	    else {
		@octets1 = split(/\./, $endpoints[0]);
		$newend = "$octets1[0].$octets1[1].$octets1[2].$octets2[0]";
		$dec_start = &ip_to_decimal($endpoints[0]);
		$dec_end = &ip_to_decimal($newend);
                push @elements, &ferment("$dec_start-$dec_end");
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
    my ($address, $start, $end, $mask, $rev_mask);
    ($address, $block) = split(/\//, $bob);
    ($start, $end) = &ip_to_endpoints($address, $block);
    $mask = &find_mask($block);
    $bin_mask = &ip_to_bin($mask);
    @bits = split(//, $bin_mask);
    foreach $toggle_bait (@bits) {
	if ($toggle_bait eq "1") {
	    $toggle_bait = "0";
	}
	else {
	    $toggle_bait = "1";
	};
    };
    $inv_bin = join "",@bits;
    $inv_mask = &bin_to_ip($inv_bin);
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

	push @list_to_date, &decimal_to_ip($start);
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
	($trial_start, $trial_end) = &ip_to_endpoints(&decimal_to_ip($start),$i); # dotted
	$trial_start = &ip_to_decimal($trial_start);          # now decimal
	$trial_end = &ip_to_decimal($trial_end);

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
	    $dotted_start = &decimal_to_ip($start);
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
	$block_found = &decimal_to_ip($start);
	$start++;
	$remaining_range = "$start-$end";
	if ($start > $end) { $remaining_range = "" }
    }

    push @list_to_date, $block_found;
    return(&ferment($remaining_range,@list_to_date));

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
    $bin_address = &ip_to_bin($address);
    $cidr = $_[1];
    $zeros = "00000000000000000000000000000000";
    $ones  = "11111111111111111111111111111111";
    for ($i=0; $i<=($cidr-1); $i++) {
	substr($zeros,$i,1) = substr($bin_address,$i,1);
    substr($ones,$i,1) = substr($bin_address,$i,1)
    };
    return(&bin_to_ip($zeros), &bin_to_ip($ones));
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
    $mask = &bin_to_ip($bin);
    return($mask);
};

############################################################################

sub ip_to_decimal {
    local($address, $i, $a, $b, $c, $d);
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
    return &bin_to_ip(&decimal_to_bin($_[0]));
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
    $octets[0] = &bin_to_decimal($binoct1);
    $octets[1] = &bin_to_decimal($binoct2);
    $octets[2] = &bin_to_decimal($binoct3);
    $octets[3] = &bin_to_decimal($binoct4);
    $address = join('.',@octets);
    return($address);
};

##############################################################
# ip_to_bin
#

sub ip_to_bin {
    my($ipaddr,$x,$y);
    $ipaddr = $_[0];
    $x = &ip_to_decimal($ipaddr);
    $y = &decimal_to_bin($x);
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
