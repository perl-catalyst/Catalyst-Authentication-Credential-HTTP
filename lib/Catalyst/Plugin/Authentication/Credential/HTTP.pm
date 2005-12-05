#!/usr/bin/perl

package Catalyst::Plugin::Authentication::Credential::HTTP;
use base qw/Catalyst::Plugin::Authentication::Credential::Password/;

use strict;
use warnings;

use String::Escape ();
use URI::Escape    ();
use Catalyst       ();

our $VERSION = "0.01";

sub authenticate_http {
    my $c = shift;

    my $headers = $c->req->headers;

    if ( my ( $user, $password ) = $headers->authorization_basic ) {

        if ( my $store = $c->config->{authentication}{http}{store} ) {
            $user = $store->get_user($user);
        }

        return $c->login( $user, $password );
    }
}

sub authorization_required {
    my ( $c, %opts ) = @_;

    return 1 if $c->authenticate_http;

    $c->authorization_required_response( %opts );

    die $Catalyst::DETACH;
}

sub authorization_required_response {
    my ( $c, %opts ) = @_;
    
    $c->res->status(401);

    my @opts;

    if ( my $realm = $opts{realm} ) {
        push @opts, sprintf 'realm=%s', String::Escape::qprintable($realm);
    }

    if ( my $domain = $opts{domain} ) {
        Catalyst::Excpetion->throw("domain must be an array reference")
          unless ref($domain) && ref($domain) eq "ARRAY";

        my @uris =
          $c->config->{authentication}{http}{use_uri_for}
          ? ( map { $c->uri_for($_) } @$domain )
          : ( map { URI::Escape::uri_escape($_) } @$domain );

        push @opts, qq{domain="@uris"};
    }

    $c->res->headers->www_authenticate(join " ", "Basic", @opts);
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Credential::HTTP - HTTP Basic authentication
for Catlayst.

=head1 SYNOPSIS

    use Catalyst qw/
        Authentication
        Authentication::Store::Moose
        Authentication::Credential::HTTP
    /;

    sub foo : Local { 
        my ( $self, $c ) = @_;

        $c->authorization_required( realm => "foo" ); # named after the status code ;-)

        # either user gets authenticated or 401 is sent

        do_stuff();
    }

    # with ACL plugin
    __PACKAGE__->deny_access_unless("/path", sub { $_[0]->authenticate_http });

    sub end : Private {
        my ( $self, $c ) = @_;

        $c->authorization_required_response( realm => "foo" );
        $c->error(0);
    }

=head1 DESCRIPTION

This moduule lets you use HTTP authentication with
L<Catalyst::Plugin::Authentication>.

Currently this module only supports the Basic scheme, but upon request Digest
will also be added. Patches welcome!

=head1 METHODS

=over 4

=item authorization_required

Tries to C<authenticate_http>, and if that fails calls
C<authorization_required_response> and detaches the current action call stack.

=item authenticate_http

Looks inside C<< $c->request->headers >> and processes the basic (badly named)
authorization header.

=item authorization_required_response

Sets C<< $c->response >> to the correct status code, and adds the correct
header to demand authentication data from the user agent.

=back

=head1 AUTHORS

Yuval Kogman, C<nothingmuch@woobling.org>

Jess Robinson

=head1 COPYRIGHT & LICENSE

        Copyright (c) 2005 the aforementioned authors. All rights
        reserved. This program is free software; you can redistribute
        it and/or modify it under the same terms as Perl itself.

=cut

