# Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2015 Michael Daum http://michaeldaumconsulting.com
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
# As per the GPL, removal of this notice is prohibited.

package Foswiki::LoginManager::KerberosLogin;

use strict;
use warnings;

use Foswiki::Func();
use Foswiki::LoginManager::Session (); # SMELL: required for _loadCreateCGISession
use Foswiki::LoginManager::TemplateLogin();
our @ISA = qw( Foswiki::LoginManager::TemplateLogin );

use GSSAPI;
use MIME::Base64;

BEGIN {
  if ($Foswiki::cfg{UseLocale}) {
    require locale;
    import locale();
  }
}

sub writeDebug {
  return unless $Foswiki::cfg{Ldap}{Debug};
  print STDERR "- KerberosLogin - $_[0]\n";
}

sub new {
  my ($class, $session) = @_;

  my $this = bless($class->SUPER::new($session), $class);

  writeDebug("called new $class");
#  Foswiki::Func::registerTagHandler( 'LOGOUT', sub { return '' } );
#  Foswiki::Func::registerTagHandler( 'LOGOUTURL', sub { return '' } );

  return $this;
}

# returns user as already found in session
sub getSessionUser {
  my $this = shift;

  my $request = $this->{session}{request};
  $this->{_cgisession} = $this->_loadCreateCGISession($request)
    unless $this->{_cgisession};

  my $user = Foswiki::Sandbox::untaintUnchecked($this->{_cgisession}->param('AUTHUSER'));

  if ($user) {
    writeDebug("found user in session: $user");
    return $user;
  }

  return;
}

sub login {
  my ($this, $query, $session) = @_;

  my $response = $session->{response};
  my $request = $session->{request};

  my $found = $this->getSessionUser?1:0;

  unless ($found) {
    foreach my $val ($request->header("Authorization")) {
      if ($val =~ /^Negotiate .+$/) {
        $found = 1;
        last;
      }
    }
  }

  if ($found) {
    my $url = $session->getScriptUrl(0, 'view', $session->{webName}, $session->{topicName}, t => time());

    writeDebug("called login redirect to $url");
    $session->redirect($url);

  } else {
    writeDebug("force into auth loop");
    $response->header(
      -status => 401,
    );
  }
}

sub getUser {
  my $this = shift;

  writeDebug("called getUser()");

  unless ($Foswiki::cfg{Ldap}{KerberosKeyTab}) {
    writeDebug("keytab not defined");
    return $this->SUPER::getUser();
  }

  my $request = $this->{session}{request};
  my $response = $this->{session}{response};
  my $user = $this->getSessionUser;

  return $user if $user;

  # assert keytab to env, have to do this every time we come here
  $ENV{KRB5_KTNAME} = "FILE:$Foswiki::cfg{Ldap}{KerberosKeyTab}";
  writeDebug("keytab=$ENV{KRB5_KTNAME}");


  my $inToken;
  foreach my $val ($request->header("Authorization")) {
    if ($val =~ /^Negotiate (.+)$/) {
      $inToken = $1;
      writeDebug("found negotiation token");
      #writeDebug("inToken='$inToken");
      $inToken = decode_base64($inToken);
      last;
    } else {
      writeDebug("found another authorization header: $val");
    }
  }

  # initial
  unless (defined $inToken) {
    writeDebug("initial redirect using WWW_Authenticate");
    $response->header(
#      -status => 401, # don't send a 401 if not required; a 401 is decided based on ACLs.
      -WWW_Authenticate => 'Negotiate'
    );
    return;
  }

  my $status;
  my $context;

TRY: {
    writeDebug("calling accept context");
    $status = GSSAPI::Context::accept(
      $context,
      GSS_C_NO_CREDENTIAL,
      $inToken,
      GSS_C_NO_CHANNEL_BINDINGS,
      my $src_name,
      undef,
      my $gss_output_token,
      undef,
      undef,
      undef
    );

    # bail out on error
    $status or last;

    writeDebug("getting client name");
    $status = $src_name->display($user);

    # bail out on error
    $status or last;

    if ($user) {
      $user =~ s/@.*//;# strip off domain

      writeDebug("user=" . ($user || ''));
    }
  }

  if ($status->major != GSS_S_COMPLETE) {
    writeDebug($this->getStatusMessage($status));
  }

  return $user;
}

sub getStatusMessage {
  my ($this, $status) = @_;

  my $text = '';

  $text .= join("\n", map {"MAJOR: $_"} $status->generic_message());
  $text .= "\n".join("\n", map {"MINOR: $_"} $status->specific_message());

  return $text;
}

1;
