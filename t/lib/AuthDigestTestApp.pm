package AuthDigestTestApp;
    use Catalyst qw/
      Authentication
      Cache
      /;
    
    our %users;
    sub moose : Local {
        my ( $self, $c ) = @_;
        #$c->authenticate( { realm => 'testrealm@host.com' } );
        $c->authenticate();
        $c->res->body( $c->user->id );
    }
    my $digest_pass = Digest::MD5->new;
    $digest_pass->add('Mufasa2:testrealm@host.com:Circle Of Life');
    %users = ( 
        Mufasa  => { pass         => "Circle Of Life",          }, 
        Mufasa2 => { pass         => $digest_pass->hexdigest, },
    );
    __PACKAGE__->config->{cache}{backend} = {
        class => 'Cache::FileCache',
    };
    __PACKAGE__->config( authentication => {
        default_realm => 'testrealm@host.com',
        realms => {
            'testrealm@host.com' => {
                store => {
                    class => 'Minimal',
                    users => \%users,
                },
                credential => {
                    class => 'HTTP',
                    type  => 'digest',
                    password_type => 'clear', 
                    password_field => 'pass'
                },
            },
        },
    });
    __PACKAGE__->setup;
