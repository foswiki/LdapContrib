# Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2007-2009 Michael Daum http://michaeldaumconsulting.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
package Foswiki::LoginManager::LdapApacheLogin;

use strict;
use Assert;
use Foswiki::LoginManager::ApacheLogin;
use Foswiki::Contrib::LdapContrib;
use Foswiki::Sandbox;

@Foswiki::LoginManager::LdapApacheLogin::ISA = qw( Foswiki::LoginManager::ApacheLogin );

sub new {
  my ($class, $session) = @_;

  my $this = bless( $class->SUPER::new($session), $class );
  $this->{ldap} = Foswiki::Contrib::LdapContrib::getLdapContrib($session);
  return $this;
}

sub loadSession {
  my $this = shift;

  my $authUser = $this->SUPER::loadSession(@_);

  # explicitly untaint it as this string comes from LDAP, and all strings
  # from LDAP are tainted, even if they come via mod_ldap
  $authUser = Foswiki::Sandbox::untaintUnchecked($authUser);

  # remove kerberos realm
  $authUser =~ s/\@.*$//g if defined $authUser;

  $this->{ldap}->checkCacheForLoginName($authUser) if defined $authUser;

  return $authUser;
}

1;
