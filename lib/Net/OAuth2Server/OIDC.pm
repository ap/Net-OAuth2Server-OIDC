use strict; use warnings;

package Net::OAuth2Server::OIDC;

our $VERSION = '0.002';

package Net::OAuth2Server::OIDC::Request::Authorization;
use parent 'Net::OAuth2Server::Request::Authorization';

our $VERSION = '0.002';

sub response_type_requiring_nonce { qw( token id_token ) }
sub valid_parameter_values { (
	display => [qw( page popup touch wap )],
	prompt  => [qw( none login consent select_account )],
) }

sub validated {
	my $self = shift;
	if ( $self->scope->contains( 'openid' ) ) {
		return $self->with_error_invalid_request( 'missing parameter: nonce' )
			if ( not defined $self->param('nonce') )
			and $self->response_type->contains( $self->response_type_requiring_nonce );

		my %validate = $self->valid_parameter_values;
		my @invalid = sort grep {
			my $name = $_;
			my $value = $self->param( $name );
			defined $value and not grep $value eq $_, @{ $validate{ $name } };
		} keys %validate;
		return $self->with_error_invalid_request( "invalid value for parameter: @invalid" ) if @invalid;
	}
	else {
		return $self->with_error_invalid_request( 'id_token requested outside of openid scope' )
			if $self->response_type->contains( 'id_token' );
	}
	$self;
}

package Net::OAuth2Server::OIDC::Response;
use parent 'Net::OAuth2Server::Response';

our $VERSION = '0.002';

use MIME::Base64 ();
use JSON::WebToken ();
use Digest::SHA ();
use Carp ();

# copy-paste from newer MIME::Base64 for older versions without it
my $b64url_enc = MIME::Base64->can( 'encode_base64url' ) || sub {
	my $e = MIME::Base64::encode_base64( shift, '' );
	$e =~ s/=+\z//;
	$e =~ tr[+/][-_];
	return $e;
};

sub supported_response_types { qw( code id_token token ) }

sub for_authorization {
	my ( $class, $req, $grant ) = ( shift, @_ );
	my $self = $class->SUPER::for_authorization( @_ );
	return $self if $self->is_error or not $grant;
	$grant->create_id_token( $self, 1 ) if $req->response_type->contains( 'id_token' );
	$self;
}

sub for_token {
	my ( $class, $req, $grant ) = ( shift, @_ );
	my $self = $class->SUPER::for_token( @_ );
	return $self if $self->is_error or not $grant;
	$grant->create_id_token( $self, 0 ) if $grant->scope->contains( 'openid' );
	$self;
}

my %hashed = qw( code c_hash access_token at_hash );

sub add_id_token {
	my ( $self, $nonce, $pay, $head, $key ) = ( shift, @_ );
	Carp::croak 'missing payload' unless $pay;
	Carp::croak 'header and payload must be hashes' if grep 'HASH' ne ref, $pay, $head || ();
	$pay->{'nonce'} = $nonce if $nonce;
	my $p = $self->param;
	my $alg = ( $head && $head->{'alg'} ) || 'none';
	if ( $alg =~ /\A[A-Za-z]{2}([0-9]+)\z/ ) {
		my $sha = Digest::SHA->new( "$1" );
		while ( my ( $k, $k_hash ) = each %hashed ) {
			my $digest = exists $p->{ $k } ? $sha->reset->add( $p->{ $k } )->digest : next;
			$pay->{ $k_hash } = $b64url_enc->( substr $digest, 0, length( $digest ) / 2 );
		}
	}
	$self->add_token( id_token => JSON::WebToken->encode( $pay, $key, $alg, $head ) );
}

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Net::OAuth2Server::OIDC - An OpenID Connect server on top of Net::OAuth2Server

=head1 DISCLAIMER

B<I cannot promise that the API is fully stable yet.>
For that reason, no documentation is provided.

=head1 DESCRIPTION

A usable but tiny implementation of OpenID Connect.

This is also a demonstration of the L<Net::OAuth2Server> design.

=head1 SEE ALSO

This is a very distant descendant of the server portion of L<OIDC::Lite>.

=cut
