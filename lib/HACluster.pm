#!/usr/local/bin/perl -w
#
#

package HACluster;
use strict;
use Errno;
use POSIX;
use POSIX qw(:sys_wait_h);
use Time::HiRes qw(gettimeofday sleep);
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);
use Net::ARP;
use IO::Socket;
use IO::Poll;
use IO::Interface::Simple;
use Log::Log4perl;
use Log::Log4perl::Level;
use Data::Dumper;


my $advt_bulk_update_min_delay = 240;
my $adv_send_max_errors = 3;
my $adv_send_min_success = 3;
my $usr1_count = 0;

my $logconf = q(
        log4perl.logger.ha_cluster = INFO, Screen
        log4perl.appender.Screen=Log::Log4perl::Appender::Screen
        log4perl.appender.Screen.layout=PatternLayout
        log4perl.appender.Screen.layout.ConversionPattern=%d{yyyy/MM/dd HH:mm:ss.SSS} %p - %m%n
);

Log::Log4perl::init(\$logconf);
my $logger = Log::Log4perl->get_logger('ha_cluster');

sub new {
    my ($class, $params) = @_;

    ## check all of required options are present
    my @required = qw(id advt_ip downscript upscript);
    foreach (@required) {
        if (! defined $params->{$_}) {
            $logger->logdie("$_ is not defined");
        }
    }


    ## 
    my $node;
    $node = {
                header => {
                            id => $params->{id},
                            advbase => 1,
                            advskew => 0,
                            digest => '',
                            advt_ip => $params->{advt_ip},
                           },
                ad_to => {
                            sec => 0,
                            usec => 0
                          },
                md_to => {
                            sec => 0,
                            usec => 0
                         },
                preempt => defined $params->{preempt} || 0,
                neutral => defined $params->{neutral} || 0,
                port => $params->{port} || 5300,
                dead_ratio => $params->{dead_ratio} || 3,
                send_errors => 0,
                send_success => 0,
                delayed_arp => -1,
                state => 'INIT',
                downscript => undef,
                upscript => undef,
                upscript_pid => undef,
                xparam => defined $params->{xparam} ? $params->{xparam} : '',
                vlan_tag => defined $params->{vlan_tag} ? $params->{vlan_tag} : undef
    };

    foreach (qw(downscript upscript)) {
        if ($params->{$_}) {
            if (-x $params->{$_}) {
                $node->{$_} = $params->{$_};
            } else {
                $logger->logdie("$params->{$_} is not executable");
            }
        } else {
            $logger->logdie("$_ is not defined");
        }
    } 

    if ($params->{advbase}) {
        if ($params->{advbase} < 1) {
            $logger->logdie("advbase needs to greater than 1");
        }
        $node->{header}->{advbase} = $params->{advbase};
    }

    if ($params->{advskew}) {
        if ($params->{advskew} > 255) {
            $logger->logdie("advskew needs to be smaller than 255");
        }
        $node->{header}->{advskew} = $params->{advskew};
    }


    my $ip_info = _get_ip_info();
    if ($params->{bc_addr}) {
        $node->{bc_addr} = $params->{bc_addr};
    } else {
        $node->{bc_addr} = $ip_info->{broadcast};
    }

    unless ($node->{bc_addr}) {
        $logger->logdie("no broadcast address");
    }

    $node->{ip_info} = $ip_info;


    if ($params->{passfile}) {
        open my $fh, "<", $params->{passfile} or
            $logger->logdie("Couldn't open $params->{passfile} for read: $!");
        $node->{pass} = <$fh>;
        close $fh;
    }

    if ($params->{pass}) {
        $node->{pass} = $params->{pass};
    }
    $logger->logdie("Couldn't get password") unless $node->{pass};
    
                   
    $logger->more_logging($params->{verbose}) if $params->{verbose};
    bless $node, $class;
}


## The main state machine
##
sub run {
    my ($self) = @_;

    $self->{skt} = IO::Socket::INET->new(
                                          Proto => 'udp',
                                          LocalPort => $self->{port},
                                        );

    
    if (! $self->{skt}) {
        $self->_logdie("Couldn't create socket object: $@");
    }

    if (! $self->{skt}->sockopt(SO_BROADCAST() => 1)) {
        $self->_logdie("Couldn't set sockopt: $@");
    }

    $self->{dest} = sockaddr_in($self->{port}, inet_aton($self->{bc_addr}));
    my $poll = new IO::Poll;
    $poll->mask($self->{skt} => POLLIN);

    my $poll_sleep_seconds;
    my $time_until_advt = {};
    $self->{advt_suppress_preempt} = 0;
    $self->{usr2_received} = 0;

    ($self->{now}->{sec}, $self->{now}->{usec}) = gettimeofday;

    $self->_set_sig();
    $self->_logdebug('Starting');
    $self->_set_run();
    
    my $saved_preempt = $self->{preempt};
    my $preempt_changed = 0;
    my $master_succeed = 0;

    while (1) {
        if ($self->{retry_downscript}) {
        # retry_downscript was set in _spawn_down_script
        # so we should try _spawn_down_script() again
            if ($self->{retry_downscript} > 3) {
                $self->{retry_downscript} = 0;
                $self->_loginfo("retry_downscript reached 3 so it's reset to 0" .
                                " and there won't be new chid process spawned up");
            } else {
                $self->_loginfo("Kicking off another downscript" .
                                " because retry_downscript is true");
                $self->_spawn_down_script();
            }
        }

        if ($self->{usr2_received}) {
            $self->_loginfo("Caught signal USR2 considering going down");
            if ($self->{state} eq 'MASTER') {
                $self->_set_state('BACKUP');
                truesleep(3);
                $self->_set_run();
            }
            $self->{usr2_received} = 0;
        }


        if ($self->{state} eq 'MASTER') {
            # We demote MASTER if upscript fails
            # note: signal is caught after the state
            # has already transitioned from BACKUP to MASTER
            if ($self->{failed_script} &&
                $self->{failed_script} == $self->{upscript_pid}) {

                $master_succeed = 0;

                $self->_loginfo("Demote myself to BACKUP because " .
                                "kid $self->{failed_script} failed");

                if ($self->{preempt}) {
                    ## we should yield to peers. this prevent vip flapping
                    $self->_loginfo("Change preempt to 0");
                    $self->{preempt} = 0;
                    $preempt_changed = 1;
                }

                $self->_set_state('BACKUP');
                truesleep(3);
                $self->_set_run();

                # reset the kid ID as we've already taken action
                # with the kid ID
                $self->{failed_script} = 0;
            } else {
                # if we have consecutive succeeds, we restore previous
                # preempt value
                if ($preempt_changed) {
                    if (++$master_succeed > $adv_send_min_success) {

                        $self->{preempt} = $saved_preempt;
                        $preempt_changed = 0;

                        $self->_loginfo("Restore preempt to $saved_preempt");
                    }
                }
            }
        }

        if ($self->{ad_to}->{sec} == 0) {
            $poll_sleep_seconds = $self->{header}->{advbase};
        } else {
            ## update global clock
            ($self->{now}->{sec}, $self->{now}->{usec}) = gettimeofday;
            _timersub($self->{ad_to}, $self->{now}, $time_until_advt);

            $poll_sleep_seconds = $time_until_advt->{sec} +
                                    ($time_until_advt->{usec} / 1000 / 1000);
        }

        my $poll_to = _max(1, $poll_sleep_seconds);
        $self->_logtrace("poll timeout: ${poll_to}s");

        if ($poll->poll($poll_to) == -1 && $!{EINTR}) {
            $self->_logtrace('poll returned -1 and EINTR was caught');
            next;
        }

        if ($poll->handles(POLLHUP | POLLERR | POLLNVAL)) {
            ## Unrecoverable conditions

            if ($self->{state} eq 'MASTER') {
                $self->_spawn_down_script();
#                $self->_spawn_script("down");
            }

            $self->_logdie("POLLHUP") if $poll->handles(POLLHUP);
            $self->_logdie("POLLERR") if $poll->handles(POLLERR);
            $self->_logdie("POLLNVAL") if $poll->handles(POLLNVAL);
        }

        if ($poll->handles(POLLIN)) {
            $self->_logtrace('POLLIN ready. About to process packet');
            $self->_process_pkt();
        }


        ## update global clock
        ($self->{now}->{sec}, $self->{now}->{usec}) = gettimeofday;

        $self->_logdebug("current time: $self->{now}->{sec}" .
                             ".$self->{now}->{usec}");
        $self->_logdebug("my state: $self->{state}");

        $self->_logdebug("time to bring up master: $self->{md_to}->{sec}" .
                         ".$self->{md_to}->{usec}");

        ## enough time passed but no masters adversting
        ## so it's time to become the master
        if ($self->{md_to}->{sec} != 0 &&
             _timercmp($self->{now}, $self->{md_to}, '>')) {

            $self->_become_master();
        }

        $self->_logdebug("time to send ad: $self->{ad_to}->{sec}" .
                        ".$self->{ad_to}->{usec}");

        if ($self->{ad_to}->{sec} != 0) {
            if (_timercmp($self->{now}, $self->{ad_to}, '>')) {
                $self->_send_ad();
            } else {
                ## counting down the number of seconds remaining before
                ## sending the advertisement
                _timersub($self->{ad_to}, $self->{now}, $time_until_advt);
                my $diff_ms = ($time_until_advt->{sec} * 1000) + 
                                ($time_until_advt->{usec} / 1000);
                $self->_logtrace("ms remaing before sending ad: $diff_ms");

                if (abs($diff_ms) <= 1) {
                    $self->_send_ad();
                }
            }
        }
    }
}


sub _process_pkt {
    my ($self) = @_;

    my ($node_timeval, $remote_timeval, $data);
    my $addr = recv($self->{skt}, $data, 512, 0) or die "recv(): $!";

    my ($port, $peer) = sockaddr_in($addr);
    my $host = inet_ntoa($peer);

    ## ignore own packets
    if ($host eq $self->{ip_info}->{address}) {
        $self->_logtrace("> _process_pkt(): discard my own ($host) packet");
        return;
    }

    $self->_logtrace("> _process_pkt()");

    my @pairs = split /,/, $data;
    my $remote_data;

    foreach my $p (@pairs) {
        my ($k, $v) = split /\s+/, $p;
        $remote_data->{$k} = $v;
    }

    my $said_digest;
    my @header;
    foreach (sort keys %{$remote_data}) {
        ## construct data string without digest
        ## so that we can validate the digest
        if ($_ eq 'digest') {
            $said_digest = $remote_data->{digest};
            next;
        }
        push @header, "$_ $remote_data->{$_}";
    }
    my $data_str = join ',', @header;

    my $true_digest =  hmac_sha1_hex($data_str, $self->{pass});
    if ($said_digest ne $true_digest) {
        $self->_logwarn("wrong digest from $host");
        return;
    }

    if ($remote_data->{id} != $self->{header}->{id}) {
        $self->_logwarn("Expect id $self->{header}->{id} " .
                        "but received $remote_data->{id} from $host");
        return;
    }

    if ($remote_data->{advt_ip} ne $self->{header}->{advt_ip}) {
        $self->_logwarn("Expect $self->{header}->{advt_ip} " .
                        "but received $remote_data->{advt_ip} from $host");
        return;
    }


    $node_timeval->{sec} = $self->{header}->{advbase};

    if ($self->{advt_suppress_preempt} != 0 &&
        $self->{header}->{advskew} < $advt_bulk_update_min_delay) {
        $node_timeval->{usec} = sprintf "%d",
            ($advt_bulk_update_min_delay * 1000000 / 256);
    } else {
        $node_timeval->{usec} = sprintf "%d",
            ($self->{header}->{advskew} * 1000000 / 256);
    }

    $remote_timeval->{sec} = $remote_data->{advbase};
    $remote_timeval->{usec} = sprintf "%d",
        ($remote_data->{advskew} * 1000000 / 256);

    $self->_logdebug("preempt: $self->{preempt}");
    $self->_logdebug("own ad interval: $node_timeval->{sec}" .
                    ".$node_timeval->{usec}");
    $self->_logdebug("peer ad interval [$host]: $remote_timeval->{sec}" .
                    ".$remote_timeval->{usec}");

    if ($self->{state} eq 'INIT') {
        # do nothing
    } elsif ($self->{state} eq 'MASTER') {
        # If we receive an advertisement from a master who's going to
        # be more frequent than us, or from a master who's advertising
        # with the same frequency as us but with a lower IP address,
        # go into BACKUP state.
        if ((_timercmp($node_timeval, $remote_timeval, '>') ||
             (_timercmp($node_timeval, $remote_timeval, '==') &&
             _ipcmp($host, $self->{ip_info}->{address}, '<')))) {

            $self->_loginfo("Preferred master $host advertised: " .
                            "I am going back to BACKUP state");

            $self->_send_ad();
            $self->_set_state('BACKUP');
            $self->_set_run();

        }

        # If we receive an advertisement from a master who's advertising
        # less frequently than us, or with the same frequency as us but
        # with a higher IP address, reassert our dominance by issuing
        # another gratuitous arp.
        if ((_timercmp($node_timeval, $remote_timeval, '<') ||
             (_timercmp($node_timeval, $remote_timeval, '==') &&
                _ipcmp($host, $self->{ip_info}->{address}, '>')))) {
              $self->_logwarn("Failed to send gratuitous arp") unless
                $self->_send_gratuitous_arp();
              $self->{delayed_arp} = 2;  # and yet another in 2 ticks
              $self->_loginfo("Non-preferred master $host advertising: " .
                       "reasserting control of VIP with another gratuitous arp");
        }
    } elsif ($self->{state} eq 'BACKUP') {
        #  If we're pre-empting masters who advertise slower than us,
        #  and this one claims to be slower, treat him as down.
        if ($self->{preempt} != 0 && 
            _timercmp($node_timeval, $remote_timeval, '<')) {

            $self->_loginfo("Putting MASTER down - preemption");
            $self->_become_master();
            return;
        }

        #  If the master is going to advertise at such a low frequency
        #  that he's guaranteed to time out, we'd might as well just
        #  treat him as timed out now.
        $node_timeval->{sec} = $self->{header}->{advbase} * $self->{dead_ratio};
        if (_timercmp($node_timeval, $remote_timeval, '<')) {
            $self->_loginfo("Putting MASTER down - timeout");
            $self->_become_master();
            return;
        }

        $self->_set_run();
        return;
    }
    $self->_logtrace("< process_pkt()");
}

## _set_run
##  Determine the advertisement time
##  and the become_master time
##  based on the current state
sub _set_run {
    my ($self) = @_;

    my $timeval;

    ## update global clock
    ($self->{now}->{sec}, $self->{now}->{usec}) = gettimeofday;

    if ($self->{state} eq 'INIT') {
        $self->_set_state('BACKUP');
        $self->_set_run();
    } else {
        if ($self->{state} eq 'BACKUP') {
            $self->{ad_to}->{sec} = 0;
            $timeval->{sec} = $self->{header}->{advbase} *
                                 $self->{dead_ratio};
        } elsif ($self->{state} eq 'MASTER') {
            $timeval->{sec} = $self->{header}->{advbase};
        }
        $timeval->{usec} = sprintf "%d",
                        $self->{header}->{advskew} * 1000000 / 256;

        _timeradd($self->{now}, $timeval, $self->{md_to});
    }
}


## _set_state
##  set the new state via $self->{state}
##  and spawn down/up scripts
sub _set_state {
    my ($self, $state) = @_;

    if ($self->{state} eq $state) {
        $self->_loginfo("No state change");
        return;
    }

    $self->_loginfo("$self->{state} -> $state");
    if ($state eq 'INIT') {
        #
    } elsif ($state eq 'BACKUP') {
        if ($self->{state} ne 'INIT' || $self->{neutral} != 1) {
            ## transition from MASTER to BACKUP
            $self->_loginfo("Spawn downscript");
            $self->_spawn_down_script();
#            $self->_spawn_script("down");
        }
    } elsif ($state eq 'MASTER') {
        ## transition from BACKUP to MASTER
        $self->_loginfo("Spawn upscript");
        $self->_spawn_script("up");
    }

    $self->{state} = $state;
}

## Send gratuituous ARP for adverstised IP
sub _send_gratuitous_arp {
    my ($self) = @_;

    # NOTE: source and destination IPs are intently set to the same IP
    # Check https://wiki.wireshark.org/Gratuitous_ARP for details
    if (Net::ARP::send_packet("$self->{ip_info}->{interface}",  # Device
                              "$self->{header}->{advt_ip}",    # Source IP
                              "$self->{header}->{advt_ip}",    # Destination IP
                              "$self->{ip_info}->{hwaddr}",     # Source MAC
                              'ff:ff:ff:ff:ff:ff',              # Destinaton MAC
                              'request')) {
        return 1;   # OK
    } else {
        return 0;   # NOT OK
    }
}

sub _prep_ad {
    my ($self) = @_;

    ## construct advertisement string
    my @tmp;
    foreach (sort keys %{$self->{header}}) {
        next if $_ eq 'digest';
        push @tmp, "$_ $self->{header}->{$_}";
    }

    my $data = join ',', @tmp;
    $self->{header}->{digest} = hmac_sha1_hex($data, $self->{pass});
    $data .= ",digest $self->{header}->{digest}";

    return $data;
}

sub _send_ad {
    my ($self) = @_;

    $self->_logtrace("> _send_ad() advbase: $self->{header}->{advbase}");
    $self->_logtrace("> _send_ad() advskew: $self->{header}->{advskew}");
    $self->_logtrace("> _send_ad() advt suppress preempt: " .
                    $self->{advt_suppress_preempt});

    my ($advbase, $advskew, $timeval);
    $advbase = $self->{header}->{advbase};

    if ($self->{advt_suppress_preempt} == 0 ||
        $self->{header}->{advskew} > $advt_bulk_update_min_delay) {
        $advskew = $self->{header}->{advskew};
    } else {
        $advskew = $advt_bulk_update_min_delay;
    }

    $timeval->{sec} = $advbase;
    $timeval->{usec} = sprintf "%d", ($advskew * 1000000 / 256);

    $self->_logtrace("> _send_ad() timeval: $timeval->{sec}.$timeval->{usec}");

    my $ad = $self->_prep_ad();

    if (send($self->{skt}, "$ad", 0, $self->{dest}) == length($ad)) {
        if ($self->{send_errors} >= $adv_send_max_errors) {
            if (++$self->{send_success} >= $adv_send_min_success) {
                $self->{advt_suppress_preempt}--;
                $self->{send_errors} = 0;
            }
        } else {
            $self->{send_errors} = 0;
        }
    } else {
        ## the limit can be higher than 32767.
        if ($self->{send_errors} < 32767) {
            $self->{send_errors}++;
        }

        if ($self->{send_errors} == $adv_send_max_errors) {
            $self->{advt_suppress_preempt}++;

            if ($self->{advt_suppress_preempt} == 1) {
                $self->_send_ad();
            }
        }
        ##
        $self->{send_success} = 0;
    }

    if ($self->{delayed_arp} > 0) {
        $self->{delayed_arp}--;
    }
    if ($self->{delayed_arp} == 0) {
        if ($self->{state} eq 'MASTER') {
            $self->_logwarn("Failed to send gratuitous arp") unless
                $self->_send_gratuitous_arp();
        }
        $self->{delayed_arp} = -1;
    }

    if ($advbase != 255 || $advskew != 255) {
        _timeradd($self->{now}, $timeval, $self->{ad_to});
        $self->_logtrace("> _send_ad() time to send ad: " .
                        "$self->{ad_to}->{sec}.$self->{ad_to}->{usec}");
    }

    $self->_logdebug("advertisement sent");
}

## _become_master
##  set my state to MASTER
##  send advertisement
##  call set_run to timeout values
sub _become_master {
    my ($self) = @_;
    if ($self->{state} eq 'BACKUP') {
        $self->_set_state('MASTER');
        $self->_send_ad();
        # Schedule a delayed ARP request to deal w/ some L3 switches
        $self->{delayed_arp} = 2;
        $self->_set_run();
    }
}

sub _spawn_down_script {
    my ($self) = @_;

    if ($self->{upscript_pid} && (kill 0, $self->{upscript_pid})) {
    # If previous upscript is still running, we will
    # run downscript again
        $self->_loginfo("downscript started even though upscript" .
                        " PID $self->{upscript_pid} hasn't finished running yet");
        $self->{retry_downscript}++;
    } else {
        $self->{retry_downscript} = 0;
    }
    $self->_spawn_script("down");
}

## _spawn_script
##  fork and exec down/up script (don't want blocking calls)
sub _spawn_script {
    my ($self, $action) = @_;

    my (@parts, $full_cmd);

    if ($action eq "up") {
        push @parts, $self->{upscript};
    } else {
        push @parts, $self->{downscript};
    }

    if ($self->{vlan_tag}) {
        push @parts, "-t";
        push @parts, "$self->{vlan_tag}";
    }

    push @parts, $self->{ip_info}->{interface};
    push @parts, $self->{header}->{advt_ip};
    push @parts, $self->{xparam};
    $full_cmd = join ' ', @parts;

    my $pid = fork;

    unless (defined $pid) {
        $self->_logdie("Can't fork: $!");
    }

    if ($pid) { # parent
        if ($action eq "up") {
        # store the pid for upscript so
        # we can look it up later to
        # determine if a failed kid is for an upscript
            $self->{upscript_pid} = $pid;
        }
        $self->_loginfo("Kid $pid: $full_cmd");
    } else { # child
        exec(@parts) or $self->_logdie("Couldn't exec $full_cmd");
    }

}


## implemention of un-interupt sleep
## sleep() waits up when a signal is received
## so sleep() won't sleep the number of seconds
## you anticipate
sub truesleep {
    my ($seconds) = @_;
    my $remaining = $seconds;

    my $elapsed = sleep($remaining);
    while ($elapsed < $seconds) {
        $remaining = $seconds - $elapsed;
        $elapsed += sleep($remaining);
    }
}

##  compare IP address in decimal format
##
sub _ipcmp {
    my ($ip1, $ip2, $operator) = @_;

    if ($ip1 =~ /:/ || $ip1 =~ /:/) {
        ## ipv6 address
        ## need real implemention
        return 1;
    } else {
        my $decimal_ip1 = unpack 'N', (pack 'C4',
                                         (split '\.', $ip1));
        my $decimal_ip2 = unpack 'N', (pack 'C4',
                                         (split '\.', $ip2));

        if ($operator eq '>') {
            return 1 if $decimal_ip1 > $decimal_ip2;
        }
        if ($operator eq '<') {
            return 1 if $decimal_ip1 < $decimal_ip2;
        }
        return 0;
    }
}

##  Obtain the first interface and its IP address
##  and broadcast address
##
sub _get_ip_info {
    my @interfaces = IO::Interface::Simple->interfaces;
    my $ip_info;

    for my $ifce (@interfaces) {
        if ($ifce->is_running) {
            if ((! $ifce->is_loopback) && $ifce->is_broadcast) {
                $ip_info->{interface} = $ifce->name;
                $ip_info->{address} = $ifce->address;
                $ip_info->{broadcast} = $ifce->broadcast;
                $ip_info->{hwaddr} = $ifce->hwaddr;
                last;
            }
        }
    }
    return $ip_info;
}

## Return the bigger number
##
sub _max {
    my ($a, $b) = @_;
    $a < $b ? return $b : return $a;
}

## Add two time hashes 
## 
sub _timeradd {
    my ($t1, $t2, $output) = @_;
    $output->{sec} = $t1->{sec} + $t2->{sec};
    $output->{usec} = $t1->{usec} + $t2->{usec};

    if ($output->{usec} > 999999) {
        $output->{usec} -= 1000000;
        $output->{sec}++;
    }
}

## Subtract a time hash from another
## and stores the result into another time hash
#
sub _timersub {
    my ($t1, $t2, $output) = @_;

    my $sec = $t1->{sec};
    my $usec = $t1->{usec};

    if ($t1->{usec} < $t2->{usec}) {
        $sec--;
        $usec += 1000000;
    }


    my $sec_diff = $sec - $t2->{sec};
    my $usec_diff = $usec - $t2->{usec};

    if ($sec_diff < 0) {
        $output->{sec} = 0;
        $output->{usec} = 0;
    } else {
        $output->{sec} = $sec_diff;
        $output->{usec} = $usec_diff;
    }
}

## Compare two time hashes
sub _timercmp {
    my ($op1, $op2, $operator) = @_;

    my $decimal1 = $op1->{sec} + ($op1->{usec} / 1000000);
    my $decimal2 = $op2->{sec} + ($op2->{usec} / 1000000);

    if ($operator eq '>') {
        return 1 if $decimal1 > $decimal2;
    }
    if ($operator eq '<') {
        return 1 if $decimal1 < $decimal2;
    }
    if ($operator eq '==') {
        return 1 if $decimal1 == $decimal2;
    }
    return 0;
}

sub _logtrace {
    my ($self, $message) = @_;
    if (defined $self->{header}->{id}) {
        $logger->trace("[HACluster ID $self->{header}->{id}] $message");
    } else {
        $logger->trace("$message");
    }
}

sub _logdebug {
    my ($self, $message) = @_;
    if (defined $self->{header}->{id}) {
        $logger->debug("[HACluster ID $self->{header}->{id}] $message");
    } else {
        $logger->debug("$message");
    }
}

sub _loginfo {
    my ($self, $message) = @_;
    if (defined $self->{header}->{id}) {
        $logger->info("[HACluster ID $self->{header}->{id}] $message");
    } else {
        $logger->info("$message");
    }
}

sub _logdie {
    my ($self, $message) = @_;
    $logger->logdie("[HACluster ID $self->{header}->{id}] $message");
    if (defined $self->{header}->{id}) {
        $logger->logdie("[HACluster ID $self->{header}->{id}] $message");
    } else {
        $logger->logdie("$message");
    }
}

sub _logwarn {
    my ($self, $message) = @_;
    $logger->logwarn("[HACluster ID $self->{header}->{id}] $message");
    if (defined $self->{header}->{id}) {
        $logger->logwarn("[HACluster ID $self->{header}->{id}] $message");
    } else {
        $logger->logwarn("$message");
    }
}

sub _set_sig {
    my ($self) = @_;
    my $sigset = POSIX::SigSet->new(SIGTERM, SIGINT, SIGHUP);
    my $action = POSIX::SigAction->new(
        sub { $self->_sigterm_handler(@_); },
        $sigset,
        SA_NODEFER,
    );
    POSIX::sigaction(SIGTERM, $action);
    POSIX::sigaction(SIGINT, $action);
    POSIX::sigaction(SIGHUP, $action);

    $sigset = POSIX::SigSet->new(SIGUSR1);
    $action = POSIX::SigAction->new(
        sub { 
                my $current_level = $logger->level();
                if ($current_level == $INFO) {
                    $logger->level($DEBUG);
                } elsif ($current_level == $DEBUG) {
                    $logger->level($TRACE);
                } else {
                    # reset logging to least verbose
                    $logger->level($INFO);
                }
            },
        $sigset,
        SA_NODEFER,
    );
    POSIX::sigaction(SIGUSR1, $action);


    $sigset = POSIX::SigSet->new(SIGUSR2);
    $action = POSIX::SigAction->new(
        sub { $self->{usr2_received} = 1 },
        $sigset,
        SA_NODEFER,
    );
    POSIX::sigaction(SIGUSR2, $action);


    $sigset = POSIX::SigSet->new(SIGCHLD);
    $action = POSIX::SigAction->new(
        sub { $self->_sigchld_handler(@_); },
        $sigset,
        SA_NODEFER,
    );
    POSIX::sigaction(SIGCHLD, $action);

    return;
}

## trap term signals
## and call downscript before exiting
sub _sigterm_handler {
    my ($self, $name) = @_;
       
    $self->_loginfo("SIG${name} received");
    # execute downscript
    if ($self->{state} eq 'MASTER') {
        $self->_spawn_down_script();
#        $self->_spawn_script("down");
    }
    $self->_loginfo("Exiting");
    exit;
}

## reap kids and check their exit status
##
sub _sigchld_handler {
    my ($self) = @_;
    my $kid;
    do {
        $kid = waitpid(-1, WNOHANG);
        if ($kid > 0) {
            if (WIFEXITED($?)) {
                my $exit_val = $? >> 8;
                if ($exit_val != 0) {
                    $self->{failed_script} = $kid;
                    $self->_loginfo("Kid $kid exited with $exit_val");
                }
            } else {
                $self->{failed_script} = $kid;
                $self->_loginfo("$kid exited with alarm");
            }
        }
    } while $kid > 0;
}


1;


__END__

=head1 NAME

HACluster - High-availability clustering solution that behaves
                 very much like CARP but implemented using UDP over
                 broadcast for advertisements

=head1 SYNOPSIS

  use HACluster;

  my $params = {
                  id => 5,
                  advbase => 1,
                  advskew => 50,
                  downscript => '/bin/true',
                  upscript => '/bin/true',
                  advt_ip => '198.168.1.100',
                  pass => 'changeme!'
              };

  my $cluster = HACluster->new($params);
  $hacluster->run();

=head1 DESCRIPTION

When HACluster first runs, it starts in INIT state then
transitions to BACKUP state and listens to the network on default UDP
port 5300 to determine if it should become a master. If at any time more than 
three times the node's advertising interval (defined as the advertising base (seconds)
plus a fudge factor, the advertising skew) passes without hearing a peer's advertisement,
the node will transition itself to being a master.

Transitioning from backup to master means:

1. running the specified up script to assign the vip to the local system

2. continuously sending advertisements to the network every interval.

Transitioning from master to backup means:

1. running the specified down script to remove the vip from the local system

To understand how HACluster works, it's important to note that
the advertisement interval is not only used as the time in between which
each advertisement is sent by the master, but also as a priority
mechanism where shorter (i.e. more frequent) is better.  The interval
base and skew values are stored in the advertisement and are used
by other nodes to make certain decisions.

By default, once a node becomes the master, it will continue on
indefinitely as the master. If you like/want/need this behavior, or don't
have a preferred master, then choose the same interval on all hosts.
If for whatever reason you were to choose different intervals on the
hosts, then over time the one with the shortest interval would tend to
become the master as machines are rebooted, after failures, etc.

Also of note is a conflict resolution algorithm that in case a master
hears another, equal (in terms of its advertised interval) master, the
one with the lower IP address will remain master and the other will
immediately demote itself.  This is simply to eliminate flapping and
quickly determine who should remain master.  This situation should not
happen very often but it can.

If you want a "preferred" master to always be the master (even if another
host is already the master), add the preempt switch (--preempt or -P) and
assign a shorter interval via the advertisement base (--advbase or -b) and
skew (--advskew or -k).  This will cause the preferred node to ignore a
master who is advertising a longer interval and promote itself to master.
The old master will quickly hear the preferred node advertising a shorter
interval and immediately demote itself.

In summary, a backup will become master if:

- no one else advertises for 3 times its own advertisement interval

- you specified --preempt and it hears a master with a longer interval

and a master will become backup if:

- another master advertises a shorter interval

- another master advertises the same interval, and has a lower IP address

Useful tips:

You can send HACluster process a SIGUSR1 to toggle verbose logging.

You can send HACluster process a SIGUSR2 to have it demote itself from
master to backup, pause 3 seconds, then proceed as usual to listen for
other masters and promote itself if necessary.  This could be useful if
you wish another node to take over master.

=head2 CONSTRUCTOR

  new HACluster($params_href);

  Required parameters:

         id    Virtual IP identifier (1-255)
        pass   password
     advbase   advertisement frequency
     advskew   advertisement skew (0-255)
     advt_ip   IP address to announce for the advertisement
    upscript   run upscript to become a mster
  downscript   run downscript to become a backup

  Optional parameters:

        port   UDP port to use (default: 5300)
     verbose   To print verbose debugging messages
      xparam   Extra parameter to send to up/down scripts
     bc_addr   broadcast address to use
     preempt   Becomes a master as soon as possible
     neutral   To not run the downscript at startup
    shutdown   To run downscript at exit unless it's already in the backup state
    passfile   read password from file
  dead_ratio   The knob basically changes how long a backup server will wait for
               an unresponsive master before considering it as dead, and
               becoming the new master. In the original protocol, the ratio is 3.
               This is also the default when this command-line switch is missing.

=head2 METHOD

 run() starts the real work

