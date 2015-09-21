# Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2007-2015 Michael Daum http://michaeldaumconsulting.com
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
package Foswiki::LoginManager::LdapTemplateLogin;

=begin TML

---+ Foswiki::LoginManager::LdapTemplateLogin

This is a simple login manager to be used when authentication is done
using apache's LDAP capabilities. In addition to the normal 
<a href="%SCRIPTURLPATH{"view"}%/%SYSTEMWEB%/PerlDoc?module=Foswiki::LoginManager::TemplateLogin">Foswiki::LoginManager::TemplateLogin</a>
manager, this one adds a check to make sure the user is already cached
in <nop>LdapContrib, and that its name matches onto the configured naming conventions.

=cut

use strict;
use warnings;
use Foswiki::LoginManager::TemplateLogin ();
use Foswiki::Contrib::LdapContrib ();
use Foswiki::Sandbox ();

@Foswiki::LoginManager::LdapTemplateLogin::ISA = qw( Foswiki::LoginManager::TemplateLogin );

=begin TML

---++ ClassMethod new($session)

Construct the <nop>LdapTemplateLogin object

=cut

sub new {
  my ($class, $session) = @_;

  my $this = bless($class->SUPER::new($session), $class);

  $this->{ldap} = Foswiki::Contrib::LdapContrib::getLdapContrib($session);
  return $this;
}

=begin TML

---++ ObjectMethod loadSession()

Load the session, sanitize the login name and make sure its user information are already
cached.

=cut

sub loadSession {
  my $this = shift;

  my $authUser = $this->SUPER::loadSession(@_);
  $authUser = Foswiki::Sandbox::untaintUnchecked($authUser);

  return $this->{ldap}->loadSession($authUser);
}

1;
