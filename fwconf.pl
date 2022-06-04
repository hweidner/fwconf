#!/usr/bin/perl

#
# FWconf  version 1.0.4
#
# a firewall configuration language for Netfilter/Iptables
#
# See http://www.weidner.ch/fwconf.html for a documentation.
#
# (c) 2001-2022 by Harald Weidner <hweidner@gmx.net>
#
# This program is released under the terms of the GNU General Public License,
# version 3.
# See http://www.fsf.org/licenses/gpl.html for the full text of the GPL.
#
# THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
# APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE
# COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS"
# WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE
# RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH
# YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
# NECESSARY SERVICING, REPAIR OR CORRECTION.
#


$IPT = "/usr/sbin/iptables-legacy";
$log_spec = "--log-level info -m limit --limit 10/minute";

%proto_serv = ();
open(SERV, "< /etc/services");
while(<SERV>) {
    chomp;
    s/\#.*$//;
    s/^\s+//;
    s/\s+$//;
    next if /^$/;
    if(/^([\w\-]+)\s+(\d+)\/(tcp|udp)(\s.*|)$/) {
	$it = $1; $nr = $2; $pr = $3; $rem = $4;
	$proto_serv{"$it/$pr"} = $nr;
	if($rem ne "") {
	    $rem =~ s/^\s+//;
	    $rem .= " ";
	    while($rem ne "") {
		$rem =~ s/([\w\-]+)\s+// and $it = $1;
		$proto_serv{"$it/$pr"} = $nr;
	    }
	}
    }
}
close(SERV);
open(PROT, "< /etc/protocols");
while(<PROT>) {
    chomp;
    s/\#.*$//;
    s/^\s+//;
    s/\s+$//;
    next if /^$/;

    if(/^([\w\-]+)\s+(\d+)(\s.*|)$/) {
	$it = $1; $nr = $2; $rem = $3;
	$proto_serv{"$it/prot"} = $nr;
        if($rem ne "") {
            $rem =~ s/^\s+//;
            $rem .= " ";
            while($rem ne "") {
                $rem =~ s/([\w\-]+)\s+// and $it = $1;
                $proto_serv{"$it/prot"} = $nr;
            }
        }
    }
}
close(PROT);

if($#ARGV < 0) {
    print "Usage: fwconf.pl <config> [ <config> [...]]\n";
}

$script = <<"EOF";

# turn on spoofing protection
if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
  for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 1 > \$f
  done
fi

# set default policies
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# flush all rules
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

# allow answer packets
$IPT -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow local traffic
$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# kill packets with state NEW but no SYN
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j LOG --log-prefix "New not syn: "
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# log and kill packets with state INVALID
$IPT -A INPUT   -m state --state INVALID -j LOG --log-prefix "Invalid Input: "
$IPT -A INPUT   -m state --state INVALID -j DROP
$IPT -A OUTPUT  -m state --state INVALID -j LOG --log-prefix "Invalid Output: "
$IPT -A OUTPUT  -m state --state INVALID -j DROP
$IPT -A FORWARD -m state --state INVALID -j LOG --log-prefix "Invalid Forward: "
$IPT -A FORWARD -m state --state INVALID -j DROP

EOF


for $file (@ARGV) {
    open(CONF, "< $file") || die "Cannot read config file $file.\n";
    while(<CONF>) {
	chomp;
	s/^\s+//;
	s/\s+$//;
	s/\#.*$//;
	next if /^$/;

	if(/^group\s+([a-zA-Z]\w*)\s+(\S.+)$/) {
	    # line is a group definition
	    $gr = $1; $rem = $2 . " ";
	    if($gr eq "ALL" || $gr eq "Local") {
		print STDERR "Error in $file/$.: Keyword \"$gr\" is reserved.\n";
		exit 1;
	    }

	    if(defined($group_if{$gr}) or defined($group_ip{$gr})) {
		print STDERR "Error in $file/$.: Group \"$gr\" already defined.\n";
		exit 1;
	    }

	    while($rem ne "") {
		$rem =~ s/^(\S+)\s+// and $it = $1;
		if($it =~ /^!?\d/) {
		    # Item is an IP number
		    if($it !~ /^!?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/
		       or $1 > 255 or $2 > 255 or $3 > 255 or $4 > 255
		       or $5 > 32) {
			print STDERR "Error in $file/$.: Illegal IP number \"$it\".\n";
			exit 1;
		    }
		    push @{$group_ip{$gr}}, $it;
		} else {
		    # item is an interface
		    push @{$group_if{$gr}}, $it;
		}
	    }
	}

	elsif(/^service\s+([a-zA-Z]\w*)\s+(\S.*)$/) {
	    # line is a service definition
	    $ser = $1; $rem = $2 . " ";

	    if(defined($service{$ser})) {
		print STDERR "Error in $file/$.: service \"$ser\" already defined.\n";
		exit 1;
	    }

	    while($rem ne "") {
		$rem =~ s/^(\S+)\s+// and $it = $1;
		if($it =~ /^([\w\-\:]+)\/(tcp|udp|icmp|prot)$/) {
		    $nr = $1; $pr = $2;
		    if($nr !~ /^\d+(\:\d+)?$/ and $pr ne "icmp") {
			$nr = $proto_serv{$it};
			if(!defined($nr)) {
			    print STDERR "Error in $file/$.: service \"$it\" does not exist!\n";
			    exit 1;
			}
		    }
		    if($nr =~ /:/) {
			push @{$service{$ser}{"$pr:"}}, $nr;
		    } else {
			push @{$service{$ser}{$pr}}, $nr;
		    }
		}
		elsif(defined $service{$it}) {
		    for $k (keys %{$service{$it}}) {
			push @{$service{$ser}{$k}}, @{$service{$it}{$k}};
		    }
		}
		else {
		    print STDERR "Error in $file/$.: service \"$it\" is not defined!\n";
		    exit 1;
		}
	    }
	}

	elsif(/^(accept|reject|drop|masq|snat|dnat|redirect)(\+log|\+nolog|)\s+([\w\-\.]+)->([\w\-\.]+)(=>[[\w\-\.]+|)\s+(\S.*)$/) {
	    # real rule

	    $target = uc $1; $log = $2; $src = $3; $dst = $4;
	    $masq = $5; $rem = $6 . " ";
	    if($src ne "ALL" and $src ne "Local" and
	       !defined $group_ip{$src} and !defined $group_if{$src}) {
		print STDERR "Error in $file/$.: group \"$src\" is not defined!\n";
		exit 1;
	    }
	    if($dst ne "ALL" and $dst ne "Local" and
	       !defined $group_ip{$dst} and !defined $group_if{$dst}) {
		print STDERR "Error in $file/$.: group \"$dst\" is not defined!\n";
		exit 1;
	    }

	    if($src eq "Local" and $dst eq "Local") {
		print STDERR "Error in $file/$.: \"Local->Local\" ist not implemented yet.\n";
		exit 1;
	    }

	    if($target =~ /^(ACCEPT|REJECT|DROP)$/i) {
		if($src eq "Local") { $chain = "-A OUTPUT"; }
		elsif($dst eq "Local") { $chain = "-A INPUT"; }
		else { $chain = "-A FORWARD"; }
		$state = "-m state --state NEW";
	    } else {
		$log = "+nolog";
		if($src eq "Local") { $chain = "-t nat -A OUTPUT"; }
		elsif($target =~ /^(MASQ|SNAT)$/) {
		    $chain = "-t nat -A POSTROUTING";
		}
		else { $chain = "-t nat -A PREROUTING"; }
		if($target eq "MASQ") {
		    $target = "MASQUERADE";
		}
		$masq =~ s/^=>//;
		if($masq ne "") {
		    $target .= " --to $masq";
		}
		$state = "";
	    }

	    undef %curr;

	    if($rem ne "ALL ") {
		while($rem ne "") {
		    $rem =~ s/^(\S+)\s+// and $it = $1;
		    
		    if($it =~ /^([\w\-\:]+)\/(tcp|udp|icmp|prot)$/) {
			$nr = $1; $pr = $2;
			if($nr !~ /^\d+(\:\d+)?$/ and $pr ne "icmp") {
			    $nr = $proto_serv{$it};
			    if(!defined($nr)) {
				print STDERR "Error in line $.: service \"$it\" does not exist!\n";
				exit 1;
			    }
			}
			push @{$curr{$pr}}, $nr;
		    } elsif(defined $service{$it}) {
			for $k (keys %{$service{$it}}) {
			    push @{$curr{$k}}, @{$service{$it}{$k}};
			}
		    } else {
			print STDERR "Error in line $.: service \"$it\" is not defined!\n";
			exit 1;
		    }
		}
	    }

	    # full ruleset is now in %curr

	    undef @spec;
	    for $k (keys %curr) {
		while($#{$curr{$k}} >= 0) {
		    if($k eq "prot") {
			($this) = splice(@{$curr{$k}}, 0, 1);
			push @spec, "-p $this";
		    } elsif ($k eq "tcp" or $k eq "udp") {
			@this = splice(@{$curr{$k}}, 0, 15);
			push @spec, "-p $k -m multiport --dport ".
			    join(",", @this);
		    } elsif ($k eq "tcp:" or $k eq "udp:") {
			($this) = splice(@{$curr{$k}}, 0, 1);
			push @spec, "-p ".substr($k,0,3)." --dport $this";
		    } else {   # icmp
			($this) = splice(@{$curr{$k}}, 0, 1);
			push @spec, "-p icmp --icmp-type $this";
		    }
		}
	    }
	    if(!@spec) {
		@spec = ("");
	    }

	    if($src eq "ALL" or !@{$group_if{$src}}) {
		@source_if = ("");
	    } elsif($chain =~ /(POSTROUTING|OUTPUT)/) {
		@source_if = ("");
	    } else {
		@source_if = @{$group_if{$src}};
	    }
	    if($src eq "ALL" or !@{$group_ip{$src}}) {
		@source_ip = ("");
	    } else {
		@source_ip = @{$group_ip{$src}};
	    }
	    if($dst eq "ALL" or !@{$group_if{$dst}}) {
		@dest_if = ("");
            } elsif($chain =~ /PREROUTING/) {
                @dest_if = ("");
	    } else {
		@dest_if = @{$group_if{$dst}};
	    }
	    if($dst eq "ALL" or !@{$group_ip{$dst}}) {
		@dest_ip = ("");
	    } else {
		@dest_ip = @{$group_ip{$dst}};
	    }

	    $script .= "## $_\n";

	    for $i_sif (@source_if) {
		$sif = $i_sif;
		if($sif ne "") { $sif = "-i $sif"; }
		for $i_sip (@source_ip) {
		    $sip = $i_sip;
		    if(substr($sip, 0, 1) eq "!") { $sip = "! -s " . substr($sip, 1); }
		    elsif($sip ne "") { $sip = "-s $sip"; }
		    for $i_dif (@dest_if) {
			$dif = $i_dif;
			if($dif ne "") { $dif = "-o $dif"; }
			for $i_dip (@dest_ip) {
			    $dip = $i_dip;
			    if(substr($dip, 0, 1) eq "!") { $dip = "! -d " . substr($dip, 1); }
			    elsif($dip ne "") { $dip = "-d $dip"; }

			    for $sp (@spec) {
				$cstate = ($sp =~ /icmp/ and $sp !~ /echo-request/) ? "" : $state;
				if($log ne "+nolog") {
				    $script .= "$IPT $chain $sif $sip $dif $dip $sp $cstate -j LOG $log_spec --log-prefix=\"" . substr("$target $src->$dst", 0, 27) . ": \"\n";
				}
				$script .= "$IPT $chain $sif $sip $dif $dip $sp $cstate -j $target\n";
			    }
			}
		    }
		}
	    }
	    
	} elsif(/^iptables\s+(.*)$/) {
	    $ipt = $1;
	    $script .= "## explicit rule\n$IPT $ipt\n";

	}
	else {
	    print STDERR "Error in $file/$.: Illegal statement \"$_\"!\n";
	    exit 1;
	}

    }
    close(CONF);
}

$script =~ s/!(\S)/! $1/mg;

$script .= <<"EOF";

# Log everything else
$IPT -A INPUT   -j LOG --log-level info --log-prefix="Unknown Input: "
$IPT -A OUTPUT  -j LOG --log-level info --log-prefix="Unknown Output: "
$IPT -A FORWARD -j LOG --log-level info --log-prefix="Unknown Forward: "

# enable IP forward
echo "1" >/proc/sys/net/ipv4/ip_forward

EOF

print $script;

exit 0;
