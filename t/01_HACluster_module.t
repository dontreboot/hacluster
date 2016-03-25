use warnings;
use strict;
use File::Basename;
use Test::More tests => 13;
use HACluster;


my $dir = dirname($0);

test_isa_what();
test_required_params();

sub class_under_test {
     return 'HACluster';
}

sub test_isa_what {
    my $class  = class_under_test();
    my $object = $class->new({ id => 1,
                               advt_ip => '127.0.0.1',
                               downscript => '/bin/true',
                               upscript => '/bin/true',
                               pass => 'really?yes.' });
    isa_ok($object, $class);
    return;
}

sub test_required_params {
    my $class  = class_under_test();
    my $p = { id => 1 };

    my $object;
    eval { $object = $class->new($p) };
    like($@, qr/not defined/, "Test for missing options 1");

    $p->{advt_ip} = '192.168.10.1';
    eval { $object = $class->new($p) };
    like($@, qr/not defined/, "Test for missing options 2");

    $p->{downscript} = '/bin/bad_downscript';
    eval { $object = $class->new($p) };
    like($@, qr/not defined/, "Test for missing options 3");

    $p->{upscript} = '/bin/bad_upscript';
    eval { $object = $class->new($p) };
    like($@, qr/downscript is not executable/, "Test for missing options 4");

    $p->{downscript} = '/bin/true';
    eval { $object = $class->new($p) };
    like($@, qr/upscript is not executable/, "Test for missing options 5");

    $p->{upscript} = '/bin/true';
    eval { $object = $class->new($p) };
    like($@, qr/Couldn't get password/, "Test for missing options 6");

    $p->{pass} = 'whatever';
    eval { $object = $class->new($p) };
    ok($@ eq '', "Test for complete options");

    delete $p->{pass}; #= undef;
    $p->{passfile} = "file_not_there";
    eval { $object = $class->new($p) };
    like($@, qr/No such file or directory/,
            "Test for missing password file");

    $p->{passfile} = "$dir/test_data/passfile";
    eval { $object = $class->new($p) };
    ok($@ eq '', "Correct passfile");

    $p->{xparam} = 0;
    $object = $class->new($p);
    ok($object->{xparam} == 0, 'xparam zero test');

    $p->{xparam} = 5;
    $object = $class->new($p);
    ok($object->{xparam} == 5, 'xparam non-zero test');

    delete $p->{xparam};
    $object = $class->new($p);
    ok($object->{xparam} eq '', 'xparam empty test');
}

