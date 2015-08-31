# Wrapper for DB_File::Lock, based on the very same
# Transparently handles Unicode strings by storing them as UTF-8
# (for some reason the perldbmfilter(1) approach doesn't work)
package Foswiki::Contrib::LdapContrib::DBFileLockConvert;

use strict;
use vars qw($VERSION @ISA);

@ISA = 'DB_File::Lock';
$VERSION = '0.01';

use DB_File::Lock ();

sub FETCH {
    my ($self, $key) = @_;
    my $res = $self->SUPER::FETCH(Foswiki::encode_utf8($key));
    return $res unless defined $res;
    Foswiki::decode_utf8($res);
}

sub STORE {
    my ($self, $key, $value) = @_;
    $self->SUPER::STORE(Foswiki::encode_utf8($key), Foswiki::encode_utf8($value));
}

sub DELETE {
    my ($self, $key) = @_;
    my $res = $self->SUPER::DELETE(Foswiki::encode_utf8($key));
    return $res unless defined $res;
    Foswiki::decode_utf8($res);
}

sub EXISTS {
    my ($self, $key) = @_;
    $self->SUPER::EXISTS(Foswiki::encode_utf8($key));
}

sub FIRSTKEY {
    my $self = shift;
    map { defined $_ ? Foswiki::decode_utf8($_) : $_ } $self->SUPER::FIRSTKEY();
}

sub NEXTKEY {
    my ($self, $lastkey) = @_;
    map { defined $_ ? Foswiki::decode_utf8($_) : $_ } $self->SUPER::NEXTKEY($lastkey);
}

1;
