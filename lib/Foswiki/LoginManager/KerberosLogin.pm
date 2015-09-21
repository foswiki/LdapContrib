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

=begin TML

---+ Foswiki::LoginManager::KerberosLogin

This login manager may be used to implement single sign on based on Kerberos authentication.
For this to work you will have to set up your server as well as your browser to exchange
kerberos tickes part of the HTTP header. See [[%SYSTEMWEB%.LdapContrib#Signle_Sign_On_and_LdapContrib]] for more information.

If no ticket could be exchanged will this login manager fall back to Foswiki::LoginManager::LdapTemplateLogin

=cut

use strict;
use warnings;

use Foswiki::Func();
use Foswiki::LoginManager::Session (); # required for _loadCreateCGISession
use Foswiki::LoginManager::LdapTemplateLogin();
our @ISA = qw( Foswiki::LoginManager::LdapTemplateLogin );

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

=begin TML

---++ ClassMethod new($session)

Construct the <nop>KerberosLogin object

=cut


sub new {
  my ($class, $session) = @_;

  my $this = bless($class->SUPER::new($session), $class);

  #writeDebug("called new $class");
#  Foswiki::Func::registerTagHandler( 'LOGOUT', sub { return '' } );
#  Foswiki::Func::registerTagHandler( 'LOGOUTURL', sub { return '' } );

  return $this;
}
=begin TML

---++ ObjectMethod getSessionUser()

returns user as already found in session

=cut

sub getSessionUser {
  my $this = shift;

  writeDebug("called getSessionUser");
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

=begin TML

---++ ObjectMethod login($request, $session)

Checks for a neogitiation HTTP header and redirects to login if not.
When found we will redirect to another view to perform the actual ticket exchange.
A special url parameter =_krb_redirect= will be set to prevent multiple redirects
happening by accident.

=cut

sub login {
  my ($this, $query, $session) = @_;

  writeDebug("called login() - this=$this");

  my $response = $session->{response};
  my $request = $session->{request};

  my $found = $this->getSessionUser?1:0;

  unless ($found) {
    foreach my $val ($request->header("Authorization")) {
      if ($val =~ /^Negotiate .+$/) {
        writeDebug("no user found but got an Authorization token in http header");
        $found = 1;
        last;
      }
    }
  }

  my $krbRedirect = $request->param("_krb_redirect");
  if ($krbRedirect) {
    writeDebug("already did a krb redirect ... not again");
    $found = 0;
  }

  if ($found) {
    my $url = $session->getScriptUrl(0, 'view', $session->{webName}, $session->{topicName}, t => time(), "_krb_redirect" => 1);
    writeDebug("redirecting to view at $url");
    $session->redirect($url);
  } else {
    writeDebug("delegating to template login");
    $this->SUPER::login($query, $session);
  }
}

=begin TML

---++ ObjectMethod getUser($request, $session)

performs the actual kerberos communication to extract the remote user name from the ticket
found in the HTTP header. 

=cut

sub getUser {
  my $this = shift;

  writeDebug("called getUser() - this=$this");

  unless ($Foswiki::cfg{Ldap}{KerberosKeyTab}) {
    writeDebug("keytab not defined");
    return $this->SUPER::getUser();
  }

  unless (-r $Foswiki::cfg{Ldap}{KerberosKeyTab}) {
    writeDebug("can't read keytab $Foswiki::cfg{Ldap}{KerberosKeyTab}");
    return $this->SUPER::getUser();
  }


  my $request = $this->{session}{request};
  my $response = $this->{session}{response};
  my $user = $this->getSessionUser;

  return $user if $user;

  # assert keytab to env, have to do this every time we come here
  $ENV{KRB5_KTNAME} = "FILE:$Foswiki::cfg{Ldap}{KerberosKeyTab}";
  #writeDebug("keytab=$ENV{KRB5_KTNAME}");


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
    writeDebug("initial redirect using WWW_Authenticate for ".$request->url(-full => 1, -path => 1, -query => 1));
    $response->header(
      #-status => 401, # don't send a 401 if not required; a 401 is decided based on ACLs.
      -WWW_Authenticate => 'Negotiate'
    );
    return;
  }

  my $status;
  my $context;
  my $error;

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
    if (GSSAPI::Status::GSS_ERROR($status->major)) {
      $error = "Unable to accept security context";
      last;
    } 


    writeDebug("getting client name");
    $status = $src_name->display($user);

    # bail out on error
    if (GSSAPI::Status::GSS_ERROR($status->major)) {
      $error = "Unable to display client name";
      last;
    }

    if ($user) {
      $user =~ s/@.*//;# strip off domain

      writeDebug("user=" . ($user || ''));
    }
  }

  if ($error) {
    writeDebug("ERROR: $error".$this->_getStatusMessage($status));
    return $this->SUPER::getUser();
  }

  return $user;
}

sub _getStatusMessage {
  my ($this, $status) = @_;

  my $text = " - MAJOR: ". join(", ", $status->generic_message());
  $text .= " - MINOR: ".join(", ", $status->specific_message());

  return $text;
}

1;
