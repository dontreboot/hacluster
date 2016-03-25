use warnings;
use strict;
use Test::More tests => 16;
use Data::Validate::IP qw(is_ipv4 is_ipv6);
use HACluster;


my $hacluster = HACluster->new({ id => 1,
                               advt_ip => '127.0.0.1',
                               downscript => '/bin/true',
                               upscript => '/bin/true',
                               pass => 'really?yes.' });

test_max();
test_timeradd();
test_timersub();
test_timercmp();
test_ipcmp();
test_get_ip_info();

sub test_max {
    is(HACluster::_max(5, 6), 6, '_max(5, 6)');
    is(HACluster::_max(1, 0.99), 1, '_max(1, 0.99)');
}

sub test_timeradd {
    my $t1 = { sec => 1433453505, usec => 999999 };
    my $t2 = { sec => 1, usec => 1 };
    my $output = {};
    my $expected = { sec => 1433453507, usec => 0 };

    HACluster::_timeradd($t1, $t2, $output);
    is_deeply($output, $expected, '_timeradd(1433453505.999999, 1.1)');

    $t1 = { sec => 1433453505, usec => 0 };
    $t2 = { sec => 0, usec => 1 };
    $output = {};
    $expected = { sec => 1433453505, usec => 1 };
    HACluster::_timeradd($t1, $t2, $output);
    is_deeply($output, $expected, '_timeradd(1433453505.0, 0.1)');
}

sub test_timersub {
    my $t1 = { sec => 1433535555, usec => 765562 };
    my $t2 = { sec => 1433535554, usec => 767451 };
    my $output = {};
    my $expected = { sec => 0, usec => 998111 };

    HACluster::_timersub($t1, $t2, $output);
    is_deeply($output, $expected, '_timersub(1433535555.765562, 1433535554.767451)');

    $t1 = { sec => 1433453505, usec => 0 };
    $t2 = { sec => 1433453507, usec => 1 };
    $output = {};
    $expected = { sec => 0, usec => 0 };
    HACluster::_timersub($t1, $t2, $output);
    is_deeply($output, $expected, '_timersub(1433453505.0, 1433453507.1)');

    $t1 = { sec => 1433453509, usec => 2 };
    $t2 = { sec => 1433453507, usec => 1 };
    $output = {};
    $expected = { sec => 2, usec => 1 };
    HACluster::_timersub($t1, $t2, $output);
    is_deeply($output, $expected, '_timersub(1433453509.2, 1433453507.1)');
}

sub test_timercmp {
    my $t1 = { sec => 1433453505, usec => 0 };
    my $t2 = { sec => 1433453503, usec => 1 };

    is(HACluster::_timercmp($t1, $2, '<'), 0,
                '_timercmp(1433453505.0, 1433453503.1, "<")');
    is(HACluster::_timercmp($t1, $2, '=='), 0,
                '_timercmp(1433453505.0, 1433453503.1, "==")');
    is(HACluster::_timercmp($t1, $2, '>'), 1,
                '_timercmp(1433453505.0, 1433453503.1, ">")');
}

sub test_ipcmp {
    is(HACluster::_ipcmp("167.195.74.144", "167.195.74.145", "<"), 1,
                '_ipcmp("167.195.74.144", "167.195.74.145", "<")');
    is(HACluster::_ipcmp("167.195.74.144", "167.195.74.145", ">"), 0,
                '_ipcmp("167.195.74.144", "167.195.74.145", ">")');
    is(HACluster::_ipcmp("97.195.74.154", "167.195.74.145", ">"), 1,
                '_ipcmp("97.195.74.154", "167.195.74.145", ">")');

}

sub test_get_ip_info {
    my $ip = HACluster::_get_ip_info();
    like($ip->{interface}, qr/\w+/, "_get_ip_info interface");
    ok(is_ipv4($ip->{address}) eq $ip->{address}, "_get_ip_info address");
    ok(is_ipv4($ip->{broadcast}) eq $ip->{broadcast}, "_get_ip_info broadcast");
}

