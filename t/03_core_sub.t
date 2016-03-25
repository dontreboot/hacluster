use warnings;
use strict;
use Test::More tests => 18;
use Test::Differences;
require HACluster;



BEGIN {
    # the system closure trick
    no warnings qw(once);    # because it whines about the used only once.
    *HACluster::send = sub {
        ## pretend we does the send the ad completely
        my $ad = $_[1];
        return length($ad);
    };

    my $pid = 12345;
    *HACluster::fork = sub {
        return $pid;
    };

    *HACluster::exec = sub {
        return \@_;
    };
}



sub class_under_test {
     return 'HACluster';
}


test_prep_ad();
test_send_ad();
test_spawn_script();
test_set_state();
test_set_run();



sub test_prep_ad {
    my $class  = class_under_test();
    can_ok($class, '_prep_ad');


    my %config = ( id => 1,
                   advt_ip => '127.0.0.1',
                   downscript => '/bin/true',
                   upscript => '/bin/true',
                   pass => 'really?yes.' );

    my $object = $class->new(\%config);

    my $data = $object->_prep_ad();
    my $expected = 'advbase 1,advskew 0,advt_ip 127.0.0.1,' .
                    'id 1,digest 09748437fc0813b4e7c27563a308246307a4fe30';
    eq_or_diff($data, $expected, "Construct advertisement");
}

sub test_send_ad {
    my $class  = class_under_test();
    can_ok($class, '_send_ad');

    {
        no strict qw(refs);          ## no critic (ProhibitNoStrict)
        no warnings qw(redefine);    ## no critic (ProhibitNoWarnings)

        my $debugger = $class . '::_logdebug';
        local *{$debugger} = sub {
            my ($this, $name) = @_;
            return { 'debug' => $name };
        };


        my %config = ( id => 1,
                       advt_ip => '127.0.0.1',
                       downscript => '/bin/true',
                       upscript => '/bin/true',
                       pass => 'really?yes.' );

        my $object = $class->new(\%config);
        my $message = $object->_send_ad();
        eq_or_diff($message, { debug => "advertisement sent" }, "adverstiment sent");
    }
    return;
}

sub test_spawn_script {


    my $class  = class_under_test();
    can_ok($class, '_spawn_script');

    {
        no strict qw(refs);          ## no critic (ProhibitNoStrict)
        no warnings qw(redefine);    ## no critic (ProhibitNoWarnings)

        my $logdie = $class . '::_logdie';
        local *{$logdie} = sub {
            my ($this, $name) = @_;
            return { 'logdie' => $name };
        };

        my $logdebug = $class . '::_loginfo';
        local *{$logdebug} = sub {
            my ($this, $name) = @_;
            return { 'info' => $name };
        };



        my %config = ( id => 1,
                       advt_ip => '127.0.0.1',
                       downscript => '/bin/false',
                       upscript => '/bin/true',
                       pass => 'really?yes.' );

        my $object = $class->new(\%config);

        ## force interface to be 'eth0' for testing so
        ## that even if eth1 is the one actives in screwdriver docker instance,
        ## the test will continue to succeed
        $object->{ip_info}->{interface} = 'eth0';

        my $message = $object->_spawn_script("up");
        eq_or_diff($message, { info => 'Kid 12345: /bin/true eth0 127.0.0.1 ' },
                     "spawn up script");
        eq_or_diff($object->{upscript_pid}, "12345", "upscript_pid");



        $message = $object->_spawn_script("down");
        eq_or_diff($message, { info => 'Kid 12345: /bin/false eth0 127.0.0.1 ' },
                     "spawn down script");

        $object->{xparam} = '24';
        $message = $object->_spawn_script("up");
        eq_or_diff($message, { info => 'Kid 12345: /bin/true eth0 127.0.0.1 24' },
                     "spawn up script with xparam");

    }
    return;
}


sub test_set_state {
    my $class  = class_under_test();
    can_ok($class, '_set_state');

    {
        no strict qw(refs);          ## no critic (ProhibitNoStrict)
        no warnings qw(redefine);    ## no critic (ProhibitNoWarnings)


        my @visited;

        my $loginfo = $class . '::_loginfo';
        local *{$loginfo} = sub {
            my ($this, $name) = @_;
            push @visited, { info => "$name" };
        };

        my $spawn_script = $class . '::_spawn_script';
        local *{$spawn_script} = sub {
            my ($this, $name) = @_;
            push @visited, { spawn_script => "$name"};
        };


        my %config = ( id => 1,
                       advt_ip => '127.0.0.1',
                       downscript => '/bin/true',
                       upscript => '/bin/true',
                       pass => 'really?yes.' );

        my $object = $class->new(\%config);

        $object->{state} = 'BACKUP';
        my $message = $object->_set_state('MASTER');

        my @expected = ( { 'info' => 'BACKUP -> MASTER' },
                         { 'info' => 'Spawn upscript' },
                         { 'spawn_script' => 'up' } );
        eq_or_diff(\@visited, \@expected, "set_state to MASTER");
        eq_or_diff($object->{state}, 'MASTER', "state transitioned from BACKUP to MASTER");


        @visited = ();
        $object->{state} = 'MASTER';
        $message = $object->_set_state('BACKUP');
        @expected = ( { 'info' => 'MASTER -> BACKUP' },
                         { 'info' => 'Spawn downscript' },
                         { 'spawn_script' => 'down' } );

        eq_or_diff(\@visited, \@expected, "set_state to BACKUP");
        eq_or_diff($object->{state}, 'BACKUP', "state transitioned from MASTER to BACKUP");

        @visited = ();
        $object->{state} = 'MASTER';
        $message = $object->_set_state('MASTER');
        @expected = ( { 'info' => 'No state change' }),
        eq_or_diff(\@visited, \@expected, "set_state (MASTER -> MASTER, No state change)");
    }
    return;
}



sub test_set_run {
    my $class  = class_under_test();
    can_ok($class, '_set_run');

    {
        no strict qw(refs);          ## no critic (ProhibitNoStrict)
        no warnings qw(redefine);    ## no critic (ProhibitNoWarnings)
        no warnings qw(once);    # because it whines about the used only once.


        my @visited;

        my $loginfo = $class . '::_loginfo';
        local *{$loginfo} = sub {
            my ($this, $name) = @_;
            push @visited, { info => "$name" };
        };

        my $spawn_script = $class . '::_spawn_script';
        local *{$spawn_script} = sub {
            my ($this, $name) = @_;
            push @visited, { spawn_script => "$name"};
        };

        my $set_state = $class . '::_set_state';
        local *{$set_state} = sub {
            my ($this, $name) = @_;
            push @visited, { set_state => "$name"};
        };

    
        local *HACluster::gettimeofday = sub {
            my @timeval = (1435621625, 9010);
            return @timeval;
        };

        my %config = ( id => 1,
                       advt_ip => '127.0.0.1',
                       downscript => '/bin/false',
                       upscript => '/bin/true',
                       pass => 'really?yes.' );

        my $object = $class->new(\%config);

        $object->{state} = 'BACKUP';
        $object->_set_run();
        eq_or_diff($object->{md_to}, { sec => 1435621628, usec => 9010 },
                    "set_run: md_to for BACKUP");

        $object->{state} = 'MASTER';
        $object->_set_run();
        eq_or_diff($object->{md_to}, { sec => 1435621626, usec => 9010 },
                    "set_run: md_to for BACKUP");
        
    }
}
