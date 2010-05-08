#!/usr/bin/perl
use strict;
use warnings;

use FindBin qw/$Bin/;
use lib "$Bin/lib";

use Test::More;
BEGIN {
    do {
        eval { require Test::WWW::Mechanize::Catalyst }
        and
        Test::WWW::Mechanize::Catalyst->VERSION('0.51')
    }
      or plan skip_all =>
      "Test::WWW::Mechanize::Catalyst is needed for this test";
    plan tests => 4;
}
use HTTP::Request;

use Test::More;
use Test::WWW::Mechanize::Catalyst qw/AuthTestApp/;
my $mech = Test::WWW::Mechanize::Catalyst->new;
$mech->get("http://localhost/moose");
is( $mech->status, 401, "status is 401" ) or die $mech->content;
$mech->content_lacks( "foo", "no output" );
my $r = HTTP::Request->new( GET => "http://localhost/moose" );
$r->authorization_basic(qw/foo s3cr3t/);
$mech->request($r);
is( $mech->status, 200, "status is 200" );
$mech->content_contains( "foo", "foo output" );

