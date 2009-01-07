#!/usr/bin/perl -w
BEGIN {
  foreach my $pc (split(/:/, $ENV{TWIKI_LIBS})) {
    unshift @INC, $pc;
  }
}

use Foswiki::Contrib::Build;

package DBCacheBuild;

@DBCacheBuild::ISA = ( "Foswiki::Contrib::Build" );

sub new {
  my $class = shift;
  return bless( $class->SUPER::new( "LdapContrib" ), $class );
}

$build = new DBCacheBuild();

$build->build($build->{target});
