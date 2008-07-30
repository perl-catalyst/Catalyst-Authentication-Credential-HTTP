package Catalyst::Authentication::Credential::HTTP;
use base qw/Catalyst::Component/;

use strict;
use warnings;

use String::Escape ();
use URI::Escape    ();
use Catalyst       ();
use Digest::MD5    ();

BEGIN {
    __PACKAGE__->mk_accessors(qw/_config realm/);
}

our $VERSION = "1.000";

sub new {
    my ($class, $config, $app, $realm) = @_;
    
    my $self = { _config => $config, _debug => $app->debug };
    bless $self, $class;
    
    $self->realm($realm);
    
    my $type = $self->_config->{'type'} ||= 'any';
    
    if (!grep /$type/, ('basic', 'digest', 'any')) {
        Catalyst::Exception->throw(__PACKAGE__ . " used with unsupported authentication type: " . $type);
    }
    return $self;
}

sub authenticate {
    my ( $self, $c, $realm, $auth_info ) = @_;
    my $auth;

    $auth = $self->authenticate_digest($c, $realm, $auth_info) if $self->_is_http_auth_type('digest');
    return $auth if $auth;

    $auth = $self->authenticate_basic($c, $realm, $auth_info) if $self->_is_http_auth_type('basic');
    return $auth if $auth;
    
    $self->authorization_required_response($c, $realm, $auth_info);
    die $Catalyst::DETACH;
}

sub authenticate_basic {
    my ( $self, $c, $realm, $auth_info ) = @_;

    $c->log->debug('Checking http basic authentication.') if $c->debug;

    my $headers = $c->req->headers;

    if ( my ( $username, $password ) = $headers->authorization_basic ) {
	    my $user_obj = $realm->find_user( { username => $username }, $c);
	    if (ref($user_obj)) {            
            if ($user_obj->check_password($password)) {
                $c->set_authenticated($user_obj);
                return $user_obj;
            }
        }
        else {
            $c->log->debug("Unable to locate user matching user info provided") if $c->debug;
            return;
        }
    }

    return;
}

sub authenticate_digest {
    my ( $self, $c, $realm, $auth_info ) = @_;

    $c->log->debug('Checking http digest authentication.') if $c->debug;

    my $headers       = $c->req->headers;
    my @authorization = $headers->header('Authorization');
    foreach my $authorization (@authorization) {
        next unless $authorization =~ m{^Digest};
        my %res = map {
            my @key_val = split /=/, $_, 2;
            $key_val[0] = lc $key_val[0];
            $key_val[1] =~ s{"}{}g;    # remove the quotes
            @key_val;
        } split /,\s?/, substr( $authorization, 7 );    #7 == length "Digest "

        my $opaque = $res{opaque};
        my $nonce  = $self->get_digest_authorization_nonce( $c, __PACKAGE__ . '::opaque:' . $opaque );
        next unless $nonce;

        $c->log->debug('Checking authentication parameters.')
          if $c->debug;

        my $uri         = '/' . $c->request->path;
        my $algorithm   = $res{algorithm} || 'MD5';
        my $nonce_count = '0x' . $res{nc};

        my $check = $uri eq $res{uri}
          && ( exists $res{username} )
          && ( exists $res{qop} )
          && ( exists $res{cnonce} )
          && ( exists $res{nc} )
          && $algorithm eq $nonce->algorithm
          && hex($nonce_count) > hex( $nonce->nonce_count )
          && $res{nonce} eq $nonce->nonce;    # TODO: set Stale instead

        unless ($check) {
            $c->log->debug('Digest authentication failed. Bad request.')
              if $c->debug;
            $c->res->status(400);             # bad request
            Carp::confess $Catalyst::DETACH;
        }

        $c->log->debug('Checking authentication response.')
          if $c->debug;

        my $username = $res{username};

        my $user;

        unless ( $user = $auth_info->{user} ) {
            $user = $realm->find_user( { username => $username }, $c);
        }
        unless ($user) {    # no user, no authentication
            $c->log->debug("Unable to locate user matching user info provided") if $c->debug;
            return;
        }

        # everything looks good, let's check the response
        # calculate H(A2) as per spec
        my $ctx = Digest::MD5->new;
        $ctx->add( join( ':', $c->request->method, $res{uri} ) );
        if ( $res{qop} eq 'auth-int' ) {
            my $digest =
              Digest::MD5::md5_hex( $c->request->body );    # not sure here
            $ctx->add( ':', $digest );
        }
        my $A2_digest = $ctx->hexdigest;

        # the idea of the for loop:
        # if we do not want to store the plain password in our user store,
        # we can store md5_hex("$username:$realm:$password") instead
        for my $r ( 0 .. 1 ) {

            # calculate H(A1) as per spec
            my $A1_digest = $r ? $user->password : do {
                $ctx = Digest::MD5->new;
                $ctx->add( join( ':', $username, $realm->name, $user->password ) );
                $ctx->hexdigest;
            };
            if ( $nonce->algorithm eq 'MD5-sess' ) {
                $ctx = Digest::MD5->new;
                $ctx->add( join( ':', $A1_digest, $res{nonce}, $res{cnonce} ) );
                $A1_digest = $ctx->hexdigest;
            }

            my $digest_in = join( ':',
                    $A1_digest, $res{nonce},
                    $res{qop} ? ( $res{nc}, $res{cnonce}, $res{qop} ) : (),
                    $A2_digest );
            my $rq_digest = Digest::MD5::md5_hex($digest_in);
            $nonce->nonce_count($nonce_count);
            $c->cache->set( __PACKAGE__ . '::opaque:' . $nonce->opaque,
                $nonce );
            if ($rq_digest eq $res{response}) {
                $c->set_authenticated($user);
                return 1;
            }
        }
    }
    return;
}

sub _check_cache {
    my $c = shift;

    die "A cache is needed for http digest authentication."
      unless $c->can('cache');
    return;
}

sub _is_http_auth_type {
    my ( $self, $type ) = @_;
    my $cfgtype = lc( $self->_config->{'type'} || 'any' );
    return 1 if $cfgtype eq 'any' || $cfgtype eq lc $type;
    return 0;
}

sub authorization_required_response {
    my ( $self, $c, $realm, $auth_info ) = @_;

    $c->res->status(401);
    $c->res->content_type('text/plain');
    if (exists $self->_config->{authorization_required_message}) {
        # If you set the key to undef, don't stamp on the body.
        $c->res->body($self->_config->{authorization_required_message}) 
            if defined $c->res->body($self->_config->{authorization_required_message}); 
    }
    else {
        $c->res->body('Authorization required.');
    }

    # *DONT* short circuit
    my $ok;
    $ok++ if $self->_create_digest_auth_response($c, $auth_info);
    $ok++ if $self->_create_basic_auth_response($c, $auth_info);

    unless ( $ok ) {
        die 'Could not build authorization required response. '
        . 'Did you configure a valid authentication http type: '
        . 'basic, digest, any';
    }
    return;
}

sub _add_authentication_header {
    my ( $c, $header ) = @_;
    $c->response->headers->push_header( 'WWW-Authenticate' => $header );
    return;
}

sub _create_digest_auth_response {
    my ( $self, $c, $opts ) = @_;
      
    return unless $self->_is_http_auth_type('digest');
    
    if ( my $digest = $self->_build_digest_auth_header( $c, $opts ) ) {
        _add_authentication_header( $c, $digest );
        return 1;
    }

    return;
}

sub _create_basic_auth_response {
    my ( $self, $c, $opts ) = @_;
    
    return unless $self->_is_http_auth_type('basic');

    if ( my $basic = $self->_build_basic_auth_header( $c, $opts ) ) {
        _add_authentication_header( $c, $basic );
        return 1;
    }

    return;
}

sub _build_auth_header_realm {
    my ( $self ) = @_;    

    if ( my $realm = $self->realm ) {
        my $realm_name = String::Escape::qprintable($realm->name);
        $realm_name = qq{"$realm_name"} unless $realm_name =~ /^"/;
        return 'realm=' . $realm_name;
    } 
    return;
}

sub _build_auth_header_domain {
    my ( $self, $c, $opts ) = @_;

    if ( my $domain = $opts->{domain} ) {
        Catalyst::Exception->throw("domain must be an array reference")
          unless ref($domain) && ref($domain) eq "ARRAY";

        my @uris =
          $self->_config->{use_uri_for}
          ? ( map { $c->uri_for($_) } @$domain )
          : ( map { URI::Escape::uri_escape($_) } @$domain );

        return qq{domain="@uris"};
    } 
    return;
}

sub _build_auth_header_common {
    my ( $self, $c, $opts ) = @_;

    return (
        $self->_build_auth_header_realm(),
        $self->_build_auth_header_domain($c, $opts),
    );
}

sub _build_basic_auth_header {
    my ( $self, $c, $opts ) = @_;
    return _join_auth_header_parts( Basic => $self->_build_auth_header_common( $c, $opts ) );
}

sub _build_digest_auth_header {
    my ( $self, $c, $opts ) = @_;

    my $nonce = $self->_digest_auth_nonce($c, $opts);

    my $key = __PACKAGE__ . '::opaque:' . $nonce->opaque;
   
    $self->store_digest_authorization_nonce( $c, $key, $nonce );

    return _join_auth_header_parts( Digest =>
        $self->_build_auth_header_common($c, $opts),
        map { sprintf '%s="%s"', $_, $nonce->$_ } qw(
            qop
            nonce
            opaque
            algorithm
        ),
    );
}

sub _digest_auth_nonce {
    my ( $self, $c, $opts ) = @_;

    my $package = __PACKAGE__ . '::Nonce';

    my $nonce   = $package->new;

    if ( my $algorithm = $opts->{algorithm} || $self->_config->{algorithm}) { 
        $nonce->algorithm( $algorithm );
    }

    return $nonce;
}

sub _join_auth_header_parts {
    my ( $type, @parts ) = @_;
    return "$type " . join(", ", @parts );
}

sub get_digest_authorization_nonce {
    my ( $self, $c, $key ) = @_;
    
    _check_cache($c);
    return $c->cache->get( $key );
}

sub store_digest_authorization_nonce {
    my ( $self, $c, $key, $nonce ) = @_;

    _check_cache($c);
    return $c->cache->set( $key, $nonce );
}

package Catalyst::Authentication::Credential::HTTP::Nonce;

use strict;
use base qw[ Class::Accessor::Fast ];
use Data::UUID ();

our $VERSION = '0.02';

__PACKAGE__->mk_accessors(qw[ nonce nonce_count qop opaque algorithm ]);

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new(@_);

    $self->nonce( Data::UUID->new->create_b64 );
    $self->opaque( Data::UUID->new->create_b64 );
    $self->qop('auth,auth-int');
    $self->nonce_count('0x0');
    $self->algorithm('MD5');

    return $self;
}

1;

__END__

=pod

=head1 NAME

Catalyst::Authentication::Credential::HTTP - HTTP Basic and Digest authentication
for Catalyst.

=head1 SYNOPSIS

    use Catalyst qw/
        Authentication
    /;

    __PACKAGE__->config( authentication => {
        realms => { 
            example => { 
                credential => { 
                    class => 'HTTP',
                    type  => 'any', # or 'digest' or 'basic'
                },
                store => {
                    class => 'Minimal',
                    users => {
                        Mufasa => { password => "Circle Of Life", },
                    },
                },
            },
        }
    });

    sub foo : Local {
        my ( $self, $c ) = @_;

        $c->authenticate({ realm => "example" }); 
        # either user gets authenticated or 401 is sent

        do_stuff();
    }

    # with ACL plugin
    __PACKAGE__->deny_access_unless("/path", sub { $_[0]->authenticate });

=head1 DESCRIPTION

This module lets you use HTTP authentication with
L<Catalyst::Plugin::Authentication>. Both basic and digest authentication
are currently supported.

When authentication is required, this module sets a status of 401, and
the body of the response to 'Authorization required.'. To override
this and set your own content, check for the C<< $c->res->status ==
401 >> in your C<end> action, and change the body accordingly.

=head2 TERMS

=over 4

=item Nonce

A nonce is a one-time value sent with each digest authentication
request header. The value must always be unique, so per default the
last value of the nonce is kept using L<Catalyst::Plugin::Cache>. To
change this behaviour, override the
C<store_digest_authorization_nonce> and
C<get_digest_authorization_nonce> methods as shown below.

=back

=head1 METHODS

=over 4

=item new $config, $c, $realm

Simple constructor.

=item authenticate $c, $realm, \%auth_info

Tries to authenticate the user, and if that fails calls
C<authorization_required_response> and detaches the current action call stack.

Looks inside C<< $c->request->headers >> and processes the digest and basic
(badly named) authorization header.

This will only try the methods set in the configuration. First digest, then basic.

This method just passes the options through untouched. See the next two methods for what \%auth_info can contain.

=item authenticate_basic $c, $realm, \%auth_info

=item authenticate_digest $c, $realm, \%auth_info

Try to authenticate one of the methods without checking if the method is
allowed in the configuration.

=item authorization_required_response $c, $realm, \%auth_info

Sets C<< $c->response >> to the correct status code, and adds the correct
header to demand authentication data from the user agent.

Typically used by C<authenticate>, but may be invoked manually.

%opts can contain C<domain> and C<algorithm>, which are used to build
%the digest header.

=item store_digest_authorization_nonce $c, $key, $nonce

=item get_digest_authorization_nonce $c, $key

Set or get the C<$nonce> object used by the digest auth mode.

You may override these methods. By default they will call C<get> and C<set> on
C<< $c->cache >>.

=back

=head1 CONFIGURATION

All configuration is stored in C<< YourApp->config(authentication => { yourrealm => { credential => { class => 'HTTP', %config } } } >>.

This should be a hash, and it can contain the following entries:

=over 4

=item type

Can be either C<any> (the default), C<basic> or C<digest>.

This controls C<authorization_required_response> and C<authenticate>, but
not the "manual" methods.

=item authorization_required_message

Set this to a string to override the default body content "Authorization required.", or set to undef to suppress body content being generated.

=back

=head1 RESTRICTIONS

When using digest authentication, this module will only work together
with authentication stores whose User objects have a C<password>
method that returns the plain-text password. It will not work together
with L<Catalyst::Authentication::Store::Htpasswd>, or
L<Catalyst::Authentication::Store::DBIC> stores whose
C<password> methods return a hashed or salted version of the password.

=head1 AUTHORS

Updated to current name space and currently maintained
by: Tomas Doran C<bobtfish@bobtfish.net>.

Original module by: 

=over

=item Yuval Kogman, C<nothingmuch@woobling.org>

=item Jess Robinson

=item Sascha Kiefer C<esskar@cpan.org>

=back

=head1 SEE ALSO

RFC 2617 (or its successors), L<Catalyst::Plugin::Cache>, L<Catalyst::Plugin::Authentication>

=head1 COPYRIGHT & LICENSE

        Copyright (c) 2005-2008 the aforementioned authors. All rights
        reserved. This program is free software; you can redistribute
        it and/or modify it under the same terms as Perl itself.

=cut

