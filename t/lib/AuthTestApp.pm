package AuthTestApp;
    use Catalyst qw/
      Authentication
      /;
    our %users;
    __PACKAGE__->config(authentication => {
        default_realm => 'test',
        realms => {
            test => {
                store => { 
                    class => 'Minimal',
                    users => \%users,
                },
                credential => { 
                    class => 'HTTP', 
                    type  => 'basic',
                    password_type => 'clear', 
                    password_field => 'password'
                },
            },
        },
    });
    sub auto : Private {
        my ($self, $c) = @_;
        $c->authenticate();
    }
    sub moose : Local {
        my ( $self, $c ) = @_;
	    $c->res->body( $c->user->id );
    }
    %users = (
        foo => { password         => "s3cr3t", },
    );
    __PACKAGE__->setup;
