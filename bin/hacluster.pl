#!/usr/local/bin/perl -w
#


use strict;
use HACluster;
use Getopt::Long qw(:config no_ignore_case);


my $help;
my $params;

GetOptions( "h" => \$help,
            "P" => \$params->{preempt},
            "z" => \$params->{shutdown},
            "n" => \$params->{neutral},
            "v+" => \$params->{verbose},
            "o=i" => \$params->{port},
            "p=s" => \$params->{pass},
            "f=s" => \$params->{passfile},
            "r=i" => \$params->{dead_ratio},
            "c=s" => \$params->{bc_addr},
            "s=s" => \$params->{src_ip},
            "t=i" => \$params->{vlan_tag},
            "a=s" => \$params->{advt_ip},
            "u=s" => \$params->{upscript},
            "d=s" => \$params->{downscript},
            "x=s"  => \$params->{xparam},
            "b=i" => \$params->{advbase},
            "k=i" => \$params->{advskew},
            "i=i" => \$params->{id});


usage() if $help;

my $cluster = new HACluster($params);
$cluster->run();

sub usage {
    print <<EOT;

    $0 [options] -i <id>

    -h          this menu
    -i <id>     cluster id (1-255) (REQUIRED)
    -P          preempt: becomes a master as soon as possible
    -z          run downscript at shutdown
    -v          verbose mode (more verbose if multiple '-v' are given)
    -o <port>   UDP port to listen on
    -r <int>    dead ratio: ratio to consider a host as dead
    -c <ip>     broadcast address to send data to
    -s <ip>     source IP: source (real) IP address of that host
    -p <pass>   password (REQUIRED unless '-f' is given)
    -f <file>   password file (REQUIRED unless '-p' is given)
    -a <ip>     advertised IP (REQUIRED)
    -u <file>   UP script (REQUIRED)
    -d <file>   DOWN script (REQUIRED)
    -x <str>    extra parameter to send to up/down scripts
    -n          neutral: don't run downscript at start if backup
    -b <int>    advertisement frequency
    -k <int>    advertisement skew (0-255)
    -t <int>    VLAN ID for 802.1Q VLAN tagging

EOT
    exit;
}
