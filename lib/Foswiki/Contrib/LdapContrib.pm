# Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2006-2015 Michael Daum http://michaeldaumconsulting.com
# Portions Copyright (C) 2006 Spanlink Communications
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

package Foswiki::Contrib::LdapContrib;

use strict;
use warnings;

use Net::LDAP qw(LDAP_REFERRAL);
use URI::ldap;
use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_SIZELIMIT_EXCEEDED LDAP_CONTROL_PAGED);
use Net::LDAP::Extension::SetPassword;
use DB_File::Lock;
use Encode ();

use Foswiki::Func ();
use Foswiki::Plugins ();

our $VERSION = '7.31';
our $RELEASE = '21 Sep 2015';
our $SHORTDESCRIPTION = 'LDAP services for Foswiki';
our $NO_PREFS_IN_TOPIC = 1;
our %sharedLdapContrib;

=pod

---+ Foswiki::Contrib::LdapContrib

General LDAP services module. This class encapsulates the platform-specific
means to integrate an LDAP directory service.  Used by Foswiki::Users::LdapPasswdUser
for authentication, Foswiki::Users::LdapUserMapping for group definitions and
Foswiki:Plugins/LdapNgPlugin to interface general query services.

---++ Typical usage
<verbatim>
my $ldap = new Foswiki::Contrib::LdapContrib;

$ldap->search(
  filter => 'mail=*@gmx*',
  callback => sub {
    my ($ldap, $entry) = @_;
    # process entry
  } 
);
my $errorMsg = $ldap->getError();

my $count = $result->count();

my @entries = $result->sorted('sn');
my $entry = $result->entry(0);

my $value = $entry->get_value('cn');
my @emails = $entry->get_value('mail');
</verbatim>

---++ Cache storage format

The cache stores a series of key-value pairs in a DB_File. The following
keys are used:

   * WIKINAMES - list of all wikiNames
   * LOGINNAMES - list of all loginNames
   * GROUPS - list of all groups
   * UNKWNUSERS - list of all usernames that could not be found in LDAP (to avoid future LDAP lookups in case caching is OFF)
   * UNKWNGROUPS - list of all group names that could not be found in LDAP (to avoid future LDAP lookups in case caching is OFF)
   * GROUPS::$groupName - list of all loginNames in group groupName (membership)
   * GROUP2UNCACHEDMEMBERSDN::$groupName - list of all DNs (when in memberIndirection mode) that could not be resolved to a user or group existing in the cache when $groupName was retreived from LDAP
   * EMAIL2U::$emailAddr - stores the loginName of an emailAddr
   * U2EMAIL::$loginName - stores the emailAddr of a loginName 
   * U2W::$loginName - stores the wikiName of a  loginName
   * W2U::$wikiName - stores the loginName of a wikiName
   * DN2U::$dn - stores the loginName of a distinguishedName
   * U2DN::$loginName - stores the distinguishedName of a loginName

=cut

=pod

---++ writeDebug($msg) 

Static Method to write a debug messages. 

=cut

sub writeDebug {
  print STDERR "- LdapContrib - $_[0]\n" if $Foswiki::cfg{Ldap}{Debug};
}

=pod

---++ writeWarning($msg) 

Static Method to write a warning messages. 

=cut

sub writeWarning {
  print STDERR "- LdapContrib - WARNING: $_[0]\n";
}

=pod

---++ new($session, host=>'...', base=>'...', ...) -> $ldap

Construct a new Foswiki::Contrib::LdapContrib object

Possible options are:
   * host: ip address (or hostname) 
   * base: the base DN to use in searches
   * port: port address used when binding to the LDAP server
   * version: protocol version 
   * userBase: list of sub-trees containing user accounts
   * groupBase: list of sub-trees containing group definitions
   * loginAttribute: user login name attribute
   * loginFilter: filter to be used to find login accounts
   * groupAttribute: the group name attribute 
   * groupFilter: filter to be used to find groups
   * memberAttribute: the attribute that should be used to collect group members
   * innerGroupAttribute: the attribute that should be used to collect inner groups of a group
   * bindDN: the dn to use when binding to the LDAP server
   * bindPassword: the password used when binding to the LDAP server

Options not passed to the constructor are taken from the global settings
in =lib/LocalSite.cfg=.

=cut

sub new {
  my $class = shift;
  my $session = shift;

  # setting the SESSION var rather early; some foswiki engines do that a bit
  # later than calling for a login manager. that will cause all sorts of
  # problems as the Foswiki::Func API can't be used then. see Item10084
  $Foswiki::Plugins::SESSION = $session;

  my $this = {
    ldap => undef,    # connect later
    error => undef,
    host => $Foswiki::cfg{Ldap}{Host} || 'localhost',
    base => $Foswiki::cfg{Ldap}{Base} || '',
    port => $Foswiki::cfg{Ldap}{Port} || 389,
    version => $Foswiki::cfg{Ldap}{Version} || 3,
    ipv6 => $Foswiki::cfg{Ldap}{IPv6} || 0,

    userBase => $Foswiki::cfg{Ldap}{UserBase}
      || [$Foswiki::cfg{Ldap}{Base}]
      || [],

    userScope => $Foswiki::cfg{Ldap}{UserScope}
      || 'sub',

    groupBase => $Foswiki::cfg{Ldap}{GroupBase}
      || $Foswiki::cfg{Ldap}{Base}
      || [],

    groupScope => $Foswiki::cfg{Ldap}{GroupScope}
      || 'sub',

    loginAttribute => $Foswiki::cfg{Ldap}{LoginAttribute} || 'uid',
    allowChangePassword => $Foswiki::cfg{Ldap}{AllowChangePassword} || 0,

    wikiNameAttribute => $Foswiki::cfg{Ldap}{WikiNameAttributes}
      || $Foswiki::cfg{Ldap}{WikiNameAttribute}
      || 'cn',

    wikiNameAliases => $Foswiki::cfg{Ldap}{WikiNameAliases} || '',

    userMappingTopic => $Foswiki::cfg{Ldap}{UserMappingTopic} || '',

    normalizeWikiName => $Foswiki::cfg{Ldap}{NormalizeWikiNames},
    normalizeLoginName => $Foswiki::cfg{Ldap}{NormalizeLoginNames},
    caseSensitiveLogin => $Foswiki::cfg{Ldap}{CaseSensitiveLogin} || 0,
    normalizeGroupName => $Foswiki::cfg{Ldap}{NormalizeGroupNames},
    ignorePrivateGroups => $Foswiki::cfg{Ldap}{IgnorePrivateGroups},

    loginFilter => $Foswiki::cfg{Ldap}{LoginFilter} || 'objectClass=posixAccount',

    groupAttribute => $Foswiki::cfg{Ldap}{GroupAttribute} || 'cn',
    primaryGroupAttribute => $Foswiki::cfg{Ldap}{PrimaryGroupAttribute} || 'gidNumber',
    groupFilter => $Foswiki::cfg{Ldap}{GroupFilter} || 'objectClass=posixGroup',
    memberAttribute => $Foswiki::cfg{Ldap}{MemberAttribute} || 'memberUid',
    innerGroupAttribute => $Foswiki::cfg{Ldap}{InnerGroupAttribute} || 'uniquegroup',
    memberIndirection => $Foswiki::cfg{Ldap}{MemberIndirection} || 0,
    nativeGroupsBackoff => $Foswiki::cfg{Ldap}{WikiGroupsBackoff} || 0,
    bindDN => $Foswiki::cfg{Ldap}{BindDN} || '',
    bindPassword => $Foswiki::cfg{Ldap}{BindPassword} || '',
    mapGroups => $Foswiki::cfg{Ldap}{MapGroups} || 0,
    rewriteGroups => $Foswiki::cfg{Ldap}{RewriteGroups} || {},
    rewriteWikiNames => $Foswiki::cfg{Ldap}{RewriteWikiNames} || {},
    rewriteLoginNames=>$Foswiki::cfg{Ldap}{RewriteLoginNames} || {},
    mergeGroups => $Foswiki::cfg{Ldap}{MergeGroups} || 0,

    mailAttribute => $Foswiki::cfg{Ldap}{MailAttribute} || 'mail',

    exclude => $Foswiki::cfg{Ldap}{Exclude}
      || 'WikiGuest, ProjectContributor, RegistrationAgent, AdminGroup, NobodyGroup',

    pageSize => $Foswiki::cfg{Ldap}{PageSize},
    isConnected => 0,
    maxCacheAge => $Foswiki::cfg{Ldap}{MaxCacheAge},
    preCache => $Foswiki::cfg{Ldap}{Precache},

    useSASL => $Foswiki::cfg{Ldap}{UseSASL} || 0,
    saslMechanism => $Foswiki::cfg{Ldap}{SASLMechanism} || 'PLAIN CRAM-MD4 EXTERNAL ANONYMOUS',

    useTLS => $Foswiki::cfg{Ldap}{UseTLS} || 0,
    tlsVerify => $Foswiki::cfg{Ldap}{TLSVerify} || 'require',
    tlsSSLVersion => $Foswiki::cfg{Ldap}{TLSSSLVersion} || 'tlsv1',
    tlsCAFile => $Foswiki::cfg{Ldap}{TLSCAFile} || '',
    tlsCAPath => $Foswiki::cfg{Ldap}{TLSCAPath} || '',
    tlsClientCert => $Foswiki::cfg{Ldap}{TLSClientCert} || '',
    tlsClientKey => $Foswiki::cfg{Ldap}{TLSClientKey} || '',

    secondaryPasswordManager => $Foswiki::cfg{Ldap}{SecondaryPasswordManager} || '',
    @_
  };
  bless($this, $class);

  $this->{session} = $session;

  $this->{preCache} = 1 unless defined $this->{preCache};
  $this->{pageSize} = 200 unless defined $this->{pageSize};

  unless (ref($this->{userBase})) {
    push @{$this->{userBase}}, $this->{userBase};
  }

  unless (ref($this->{groupBase})) {
    push @{$this->{groupBase}}, $this->{groupBase};
  }

  if ($this->{useSASL}) {
    #writeDebug("will use SASL authentication");
    require Authen::SASL;
  }

  # protect against actidental misconfiguration, that might lead
  # to an infinite loop during authorization etc.
  if ($this->{secondaryPasswordManager} eq 'Foswiki::Users::LdapPasswdUser') {
    writeWarning("hey, you want infinite loops? naw.");
    $this->{secondaryPasswordManager} = '';
  }

  if ($this->{secondaryPasswordManager} eq 'none') {
    $this->{secondaryPasswordManager} = '';
  }

  my $workArea = $session->{store}->getWorkArea('LdapContrib');
  mkdir $workArea unless -d $workArea;
  $this->{cacheFile} = $workArea . '/cache.db';

  # Locking parameters 
  $this->{locking}{'nonblocking'} = 0; # wait, not croak if lock is set
  $this->{locking}{'lockfile_name'} = $this->{cacheFile} . '.lock';
  $this->{locking}{'lockfile_mode'} = 0600;

  # normalize normalization flags
  $this->{normalizeWikiName} = $Foswiki::cfg{Ldap}{NormalizeWikiName}
    unless defined $this->{normalizeWikiName};
  $this->{normalizeWikiName} = 1
    unless defined $this->{normalizeWikiName};
  $this->{normalizeLoginName} = $Foswiki::cfg{Ldap}{NormalizeLoginName}
    unless defined $this->{normalizeLoginName};
  $this->{normalizeGroupName} = $Foswiki::cfg{Ldap}{NormalizeGroupName}
    unless defined $this->{normalizeGroupName};

  @{$this->{wikiNameAttributes}} = split(/\s*,\s*/, $this->{wikiNameAttribute});

  # create exclude map
  my %excludeMap;
  if ($this->{caseSensitiveLogin}) {
    %excludeMap = map { $_ => 1 } split(/\s*,\s*/, $this->{exclude});
  } else {
    %excludeMap = map { $_ => 1, lc($_) => 1 } split(/\s*,\s*/, $this->{exclude});
  }
  $this->{excludeMap} = \%excludeMap;

  # creating alias map
  my %aliasMap = ();
  foreach my $alias (split(/\s*,\s*/, $this->{wikiNameAliases})) {
    if ($alias =~ /^\s*(.+?)\s*=\s*(.+?)\s*$/) {
      $aliasMap{$1} = $2;
    }
  }
  $this->{wikiNameAliases} = \%aliasMap;

  # default value for cache expiration is every 24h
  $this->{maxCacheAge} = 86400 unless defined $this->{maxCacheAge};

  #writeDebug("constructed a new LdapContrib object");

  return $this;
}

=pod

---++ getLdapContrib($session) -> $ldap

Returns a standard singleton Foswiki::Contrib::LdapContrib object based on the site-wide
configuration. 

=cut

sub getLdapContrib {
  my $session = shift;

  my $obj = $sharedLdapContrib{$session};
  return $obj if $obj;

  $obj = new Foswiki::Contrib::LdapContrib($session);
  $obj->initCache();
  $sharedLdapContrib{$session} = $obj;

  return $obj;
}

=pod

---++ connect($dn, $passwd, $host, $port) -> $boolean

Connect to LDAP server. If a $dn parameter and a $passwd is given then a bind is done.
Otherwise the communication is anonymous. You don't have to connect() explicitely
by calling this method. The methods below will do that automatically when needed.

=cut

sub connect {
  my ($this, $dn, $passwd, $host, $port) = @_;

  #writeDebug("called connect");
  #writeDebug("dn=$dn") if $dn;
  #writeDebug("passwd=***", 2) if $passwd;

  $host ||= $this->{host};
  $port ||= $this->{port};

  $this->{ldap} = Net::LDAP->new(
    $host,
    port => $port,
    version => $this->{version},
    inet4 => ($this->{ipv6}?0:1),
    inet6 => ($this->{ipv6}?1:0),
    timeout => 5, # TODO: make configurable
  );

  unless ($this->{ldap}) {
    $this->{error} = "failed to connect to $this->{host}";
    $this->{error} .= ": $@" if $@;
    #writeDebug("failed to connect: $this->{error}");
    $this->{isConnected} = 0;
    return 0;
  }

  # TLS bind
  if ($this->{useTLS}) {
    #writeDebug("using TLS");
    my %args = (
      verify => $this->{tlsVerify},
      cafile => $this->{tlsCAFile},
      capath => $this->{tlsCAPath},
    );
    $args{"clientcert"} = $this->{tlsClientCert} if $this->{tlsClientCert};
    $args{"clientkey"} = $this->{tlsClientKey} if $this->{tlsClientKey};
    $args{"sslversion"} = $this->{tlsSSLVersion} if $this->{tlsSSLVersion};
    my $msg = $this->{ldap}->start_tls(%args);
    writeWarning($msg->{errorMessage}) if $msg->{errorMessage};
  }

  $passwd = $this->toSiteCharSet($passwd) if $passwd;

  # authenticated bind
  my $msg;
  if (defined($dn)) {
    die "illegal call to connect()" unless defined($passwd);
    $msg = $this->{ldap}->bind($dn, password => $passwd);
    #writeDebug("bind for $dn");
  }

  # sasl bind
  elsif ($this->{useSASL}) {
    my $sasl = Authen::SASL->new(
      mechanism => $this->{saslMechanism},    #'DIGEST-MD5 PLAIN CRAM-MD5 EXTERNAL ANONYMOUS',
    );

    if ($this->{bindDN} && $this->{bindPassword}) {
      $sasl->callback(
        user => $this->{bindDN},
        pass => $this->{bindPassword},
      );
      #writeDebug("sasl bind to $this->{bindDN}");
      $msg = $this->{ldap}->bind($this->{bindDN}, sasl => $sasl, version => $this->{version});

    } else {
      # writeDebug("sasl bind without user or pass");
      $msg = $this->{ldap}->bind(sasl => $sasl, version => $this->{version});
    }

  } 

  # simple bind
  elsif ($this->{bindDN} && $this->{bindPassword}) {
    #writeDebug("proxy bind");
    $msg = $this->{ldap}->bind($this->{bindDN}, password => $this->{bindPassword});
  }

  # anonymous bind
  else {
    #writeDebug("anonymous bind");
    $msg = $this->{ldap}->bind;
  }

  $this->{isConnected} = ($this->checkError($msg) == LDAP_SUCCESS) ? 1 : 0;
  #writeDebug("failed to bind") unless $this->{isConnected};
  return $this->{isConnected};
}

=pod

---++ disconnect()

Unbind the LDAP object from the server. This method can be used to force
a reconnect and possibly rebind as a different user.

=cut

sub disconnect {
  my $this = shift;

  return unless defined($this->{ldap}) && $this->{isConnected};

  #writeDebug("called disconnect()");
  $this->{ldap}->unbind();
  $this->{ldap} = undef;
  $this->{isConnected} = 0;
}

=pod

---++ finish()

finalize this ldap object.

=cut

sub finish {
  my $this = shift;

  return if $this->{isFinished};
  $this->{isFinished} = 1;

  #writeDebug("finishing");

  $this->disconnect();
  delete $sharedLdapContrib{$this->{session}};

  undef $this->{_topicUserMapping};
  undef $this->{_wikiNameClaches};
  undef $this->{_primaryGroup};
  undef $this->{_groups};
  undef $this->{_groupId};

  $this->untieCache();
}

=pod

---++ checkError($msg) -> $errorCode

Private method to check a Net::LDAP::Message object for an error, sets
$ldap->{error} and returns the ldap error code. This method is called
internally whenever a message object is returned by the server. Use
$ldap->getError() to return the actual error message.

=cut

sub checkError {
  my ($this, $msg) = @_;

  my $code = $this->{code} = $msg->code();
  if ($code == LDAP_SUCCESS || $code == LDAP_REFERRAL) {
    $this->{error} = undef;
  } else {
    $this->{error} = $code . ': ' . $msg->error();
    #writeDebug($this->{error});
  }

  return $code;
}

=pod

---++ getError() -> $errorMsg

Returns the error message of the last LDAP action or undef it no
error occured.

=cut

sub getError {
  return $_[0]->{error};
}

=pod

---++ getCode() -> $errorCode

Returns the error code of the last LDAP action

=cut

sub getCode {
  return $_[0]->{code};
}

=pod

---++ getAccount($loginName) -> Net::LDAP::Entry object

Fetches an account entry from the database and returns a Net::LDAP::Entry
object on success and undef otherwise. Note, the login name is match against
the attribute defined in $ldap->{loginAttribute}. Account records are 
search using $ldap->{loginFilter} in one of the the subtrees defined in
$ldap->{userBase}.

=cut

sub getAccount {
  my ($this, $loginName) = @_;

  return undef if $this->{excludeMap}{$loginName};
  writeDebug("called getAccount($loginName)");

  # take care of login case
  $loginName = lc($loginName) unless $this->{caseSensitiveLogin};

  my $loginFilter = $this->{loginFilter};
  $loginFilter = "($loginFilter)" unless $loginFilter =~ /^\(.*\)$/;
  my $filter = '(&' . $loginFilter . '(' . $this->{loginAttribute} . '=' . $loginName . '))';

  my $entry;
  foreach my $userBase (@{$this->{userBase}}) {
    my $msg = $this->search(
      filter => $filter,
      base => $userBase,
      deref => "always",
      callback => sub {
        my (undef, $result) = @_;
        return unless defined $result;
        $entry = $result;
      }
    );

    return $entry if $entry;
  }

  $this->{error} = 'Login invalid';
  writeDebug($this->{error});

  return;
}

=pod

---++ search($filter, %args) -> $msg

Returns an Net::LDAP::Search object for the given query on success and undef
otherwise. If $args{base} is not defined $ldap->{base} is used.  If $args{scope} is not
defined 'sub' is used (searching down the subtree under $args{base}. If no $args{sizelimit} is
set all matching records are returned.  The $attrs is a reference to an array
of all those attributes that matching entries should contain.  If no $args{attrs} is
defined all attributes are returned.

If undef is returned as an error occured use $ldap->getError() to get the
cleartext message of this search() operation.

Typical usage:
<verbatim>
$ldap->search(
  filter=>'uid=TestUser',
  callback => sub {
    my ($ldap, $entry) = @_;
    return unless defined $entry;
    # process entry
  }
);
</verbatim>

=cut

sub search {
  my ($this, %args) = @_;

  $args{base} = $this->{base} unless $args{base};
  $args{base} = $this->toSiteCharSet($args{base});
  $args{scope} = 'sub' unless $args{scope};
  $args{sizelimit} = 0 unless $args{sizelimit};
  $args{attrs} = ['*'] unless $args{attrs};
  $args{filter} = $this->toSiteCharSet($args{filter}) if $args{filter};

  if (defined($args{callback}) && !defined($args{_origCallback})) {

    $args{_origCallback} = $args{callback};

    $args{callback} = sub {
      my ($ldap, $entry) = @_;

      # bail out when done
      return unless defined $entry;

      # follow references
      if ($entry->isa("Net::LDAP::Reference")) {
        foreach my $link ($entry->references) {
          writeDebug("following reference $link");
          $this->_followLink($link, %args);
        }
      } else {
        # call the orig callback
        $args{_origCallback}($ldap, $entry);
      }
    };
  }

  if ($Foswiki::cfg{Ldap}{Debug}) {
    my $attrString = join(',', @{$args{attrs}});
    writeDebug("called search(filter=$args{filter}, base=$args{base}, scope=$args{scope}, sizelimit=$args{sizelimit}, attrs=$attrString)");
  }

  unless ($this->{ldap}) {
    unless ($this->connect()) {
      writeDebug("error in search: " . $this->getError());
      return undef;
    }
  }

  my $msg = $this->{ldap}->search(%args);
  my $errorCode = $this->checkError($msg);

  # we set a sizelimit so it is ok that it exceeds
  if ($args{sizelimit} && $errorCode == LDAP_SIZELIMIT_EXCEEDED) {
    writeDebug("sizelimit exceeded");
    return $msg;
  }

  if ($errorCode == LDAP_REFERRAL) {
    unless ($this->{_followingLink}) {
      my @referrals = $msg->referrals;
      foreach my $link (@referrals) {
        writeDebug("following referral $link");
        $this->_followLink($link, %args);
      }
    }
  } elsif ($errorCode != LDAP_SUCCESS) {
    writeDebug("error in search: " . $this->getError());
    return undef;
  }

  return $msg;
}

sub _followLink {
  my ($this, $link, %args) = @_;

  writeDebug("following ldap url $link");
  #return if $this->{_followingLink};
  $this->{_followingLink} = 1;

  my $uri = URI::ldap->new($link);

  # SMELL: cache multiple ldap connections

  # remember old connection
  my $oldLdap = $this->{ldap};
  my %thisArgs = %args;
  $thisArgs{base} = $uri->dn;
  $thisArgs{port} = $uri->port;

  # trick in new connection
  $this->connect(undef, undef, $uri->host, $uri->port);
  $this->search(%thisArgs);
  $this->disconnect;

  # restore old connection
  $this->{ldap} = $oldLdap;
  $this->{isConnected} = 1 if defined $oldLdap;

  $this->{_followingLink} = 0;

  writeDebug("done following ldap url $link");
}

=pod

---++ cacheBlob($entry, $attribute, $refresh) -> $pubUrlPath

Takes an Net::LDAP::Entry and an $attribute name, and stores its value into a
file. Returns the pubUrlPath to it. This can be used to store binary large
objects like images (jpegPhotos) into the filesystem accessible to the httpd
which can serve it in return to the client browser. 

Filenames containing the blobs are named using a hash value that is generated
using its DN and the actual attribute name whose value is extracted from the 
database. If the blob already exists in the cache it is _not_ extracted once
again except the $refresh parameter is defined.

Typical usage:
<verbatim>
my $blobUrlPath = $ldap->cacheBlob($entry, $attr);
</verbatim>

=cut

sub cacheBlob {
  my ($this, $entry, $attr, $refresh) = @_;

  writeDebug("called cacheBlob()");
  require Digest::MD5;

  my $systemWeb = $Foswiki::cfg{SystemWebName};
  my $dir = $Foswiki::cfg{PubDir} . '/' . $systemWeb . '/LdapContrib';
  mkdir $dir unless -d $dir;
  $dir .= '/blobs';
  mkdir $dir unless -d $dir;

  my $key = Digest::MD5::md5_hex($entry->dn() . $attr);
  my $fileName = $dir . '/' . $key;

  if ($refresh || !-f $fileName) {
    writeDebug("caching blob for $attr to $fileName");
    my $value = $entry->get_value($attr);
    return undef unless defined $value;
    mkdir($dir, 0775) unless -e $dir;

    open(FILE, ">$fileName") || die "can't open $fileName";
    binmode(FILE);
    print FILE $value;
    close(FILE);
  } else {
    writeDebug("already got blob");
  }

  writeDebug("done cacheBlob()");
  return $Foswiki::cfg{PubUrlPath} . '/' . $systemWeb . '/LdapContrib/blobs/' . $key;
}

=pod

---++ tieCache($mode)

tie the cache with $mode. 
$mode 'read' ties the cache successfully given that there is only other 'read' locks on it.
$mode 'write' ties the cache successfully given that there is no locks on it.

=cut

sub tieCache {
  my ($this, $mode) = @_;

  die unless $mode =~ m/^read|write$/;

  my $locking = {
    'mode' => $mode,
    'nonblocking' => $this->{locking}{nonblocking},
    'lockfile_name' => $this->{locking}{lockfile_name},
    'lockfile_mode' => $this->{locking}{lockfile_mode}
  };

  # Create the cache unless it exists
  unless (-e $this->{cacheFile}) {
    $locking->{'mode'} = 'write';
    my %db_hash;
    my $x = tie(%db_hash, 'DB_File::Lock', $this->{cacheFile}, O_CREAT|O_RDWR, 0664, $DB_HASH, $locking);
    undef($x);
    untie(%db_hash);
    $locking->{'mode'} = $mode;
  }

  my $tie_flag = ($mode eq 'read' ? O_RDONLY : O_RDWR);

  $this->{cacheDB} = tie %{$this->{data}}, 'DB_File::Lock', $this->{cacheFile}, $tie_flag, 0664, $DB_HASH, $locking
    or die "Error tieing cache file $this->{cacheFile}: $!";
}


=pod

---++ untieCache()

unties the cache

=cut

sub untieCache {
  my ($this) = @_;

  undef $this->{cacheDB};
  untie %{$this->{data}};
}

=pod

---++ initCache()

loads/connects to the LDAP cache

=cut

sub initCache {
  my $this = shift;

  return
    unless $Foswiki::cfg{UserMappingManager} =~ /LdapUserMapping/
      || $Foswiki::cfg{PasswordManager} =~ /LdapPasswdUser/;

  # open cache
  #writeDebug("opening ldap cache from $this->{cacheFile}");
  $this->tieCache('read');

  # refresh by user interaction
  my $refresh = '';
  $refresh = CGI::param('refreshldap') || '';
  $refresh = 1 if $refresh eq 'on';
  $refresh = 2 if $refresh eq 'force';
  $refresh = 0 unless $refresh;

  if ($this->{maxCacheAge} > 0) {    # is cache expiration enabled

    # compute age of data
    my $cacheAge = 9999999999;
    my $now = time();
    my $lastUpdate = $this->{data}{lastUpdate} || 0;
    $cacheAge = $now - $lastUpdate if $lastUpdate;

    # don't refresh within 60 seconds
    if ($cacheAge < 10) {
      $refresh = 0;
      writeDebug("suppressing cache refresh within 10 seconds");
    } else {
      $refresh = 1 if $cacheAge > $this->{maxCacheAge};
    }

    writeDebug("cacheAge=$cacheAge, maxCacheAge=$this->{maxCacheAge}, lastUpdate=$lastUpdate, refresh=$refresh");
  }

  # clear to reload it
  $this->refreshCache($refresh);
}

=pod

---++ initTopicUserMapping()

reads a topic-based user mapping from a predefined topic and initializes the internal _topicUserMapping hash

=cut

sub initTopicUserMapping {
  my $this = shift;

  return unless $this->{userMappingTopic};

  my ($web, $topic) = Foswiki::Func::normalizeWebTopicName(undef, $this->{userMappingTopic});

  unless (Foswiki::Func::topicExists($web, $topic)) {
    writeDebug("UserMappingTopic $web.$topic not found");
    return;
  }

  writeDebug("reading topic mapping from $web.$topic");

  my ($meta, $text) = Foswiki::Func::readTopic($web, $topic);

  $this->{_topicUserMapping} = ();

  while ($text =~ /^\s*\* (?:$Foswiki::regex{webNameRegex}\.)?($Foswiki::regex{wikiWordRegex})\s*(?:-\s*(\S+)\s*)?-.*$/gm) {
    my $wikiName = $1;
    my $loginName = $2 || $wikiName;

    # can't use basemapping obj here as it doesn't exist yet
    # next if $this->{session}->{users}->{basemapping}->handlesUser(undef, $loginName, $wikiName);

    next if $wikiName =~ /^(ProjectContributor|$Foswiki::cfg{Register}{RegistrationAgentWikiName}|$Foswiki::cfg{AdminUserWikiName}|$Foswiki::cfg{DefaultUserWikiName}|UnknownUser)$/;

    writeDebug("topic mapping $wikiName - $loginName");
    $this->{_topicUserMapping}{$loginName} = $wikiName;
  }
}

=pod

---++ refreshCache($mode) -> $boolean

download all relevant records from the LDAP server and
store it into a database.

   * mode = 0: no refersh
   * mode = 1: normal refersh
   * mode = 2: nuke previous decisions on wikiName clashes

=cut

sub refreshCache {
  my ($this, $mode) = @_;

  return unless $mode;

  $this->{_refreshMode} = $mode;

  # create a temporary tie
  my $tempCacheFile = $this->{cacheFile} . '_tmp';
  if (-e $tempCacheFile) {
    writeWarning("already refreshing cache");
    return 0;
  }

  my %tempData;
  my $tempCache = tie %tempData, 'DB_File', $tempCacheFile, O_CREAT | O_RDWR, 0664, $DB_HASH
    or die "Cannot open file $tempCacheFile: $!";

  # precache the LDAP directory if enabled in configuration file
  # writeDebug("Config:" . $this->{preCache});
  if ($this->{preCache}) {
    writeDebug("precaching is ON.");

    my $isOk;

    foreach my $userBase (@{$this->{userBase}}) {
      $isOk = $this->refreshUsersCache(\%tempData, $userBase);
      last unless $isOk;
    }

    if ($isOk && $this->{mapGroups}) {
      foreach my $groupBase (@{$this->{groupBase}}) {
        $isOk = $this->refreshGroupsCache(\%tempData, $groupBase);
        last unless $isOk;
      }
    }

    unless ($isOk) {    # we had an error: keep the old cache til the error is resolved
      undef $tempCache;
      untie %tempData;
      unlink $tempCacheFile;
      return 0;
    }
  }

  #writeDebug("flushing db to disk");
  $tempData{lastUpdate} = time();
  $tempCache->sync();
  undef $tempCache;
  untie %tempData;

  # try to be transactional
  $this->untieCache();

  #writeDebug("replacing working copy");
  rename $tempCacheFile, $this->{cacheFile};

  # reconnect hash
  $this->tieCache('read');

  undef $this->{_refreshMode};

  return 1;
}

=pod

---++ refreshUsersCache($data, $userBase) -> $boolean

download all user records from the LDAP server and cache it into the
given hash reference

returns true if new records have been loaded

=cut

sub refreshUsersCache {
  my ($this, $data, $userBase) = @_;

  writeDebug("called refreshUsersCache($userBase)");
  $data ||= $this->{data};
  $userBase ||= $this->{base};

  # prepare search
  my %args = (
    filter => $this->{loginFilter},
    base => $userBase,
    scope => $this->{userScope},
    deref => "always",
    attrs => [$this->{loginAttribute}, $this->{mailAttribute}, $this->{primaryGroupAttribute}, @{$this->{wikiNameAttributes}}],
  );

  # init the topic mapping if required
  $this->initTopicUserMapping();

  # use the control LDAP extension only if a valid pageSize value has been provided
  my $page;
  my $cookie;
  if ($this->{pageSize} > 0) {
    require Net::LDAP::Control::Paged;
    $page = Net::LDAP::Control::Paged->new(size => $this->{pageSize});
    $args{control} = [$page];
    writeDebug("reading users from cache with page size=$this->{pageSize}");
  } else {
    writeDebug("reading users from cache in one chunk");
  }

  # read pages
  my $nrRecords = 0;
  my %wikiNames = ();
  my %loginNames = ();
  my $gotError = 0;

  if (defined $data->{WIKINAMES}) {
    %wikiNames = map { $_ => 1 } $data->{WIKINAMES};
  }
  if (defined $data->{LOGINNAMES}) {
    %loginNames = map { $_ => 1 } $data->{LOGINNAMES};
  }

  $args{callback} = sub {
    my ($ldap, $entry) = @_;
    $this->cacheUserFromEntry($entry, $data, \%wikiNames, \%loginNames) && $nrRecords++;
  };

  while (1) {

    # perform search
    my $mesg = $this->search(%args);
    unless ($mesg) {
      writeWarning("error refreshing the user cache: " . $this->getError());
      my $code = $this->getCode();
      $gotError = 1 if !defined($code) || $code != LDAP_SIZELIMIT_EXCEEDED;    # continue on sizelimit exceeded
      last;
    }

    # only use cookies and pages if we are using this extension
    if ($page) {
      # get cookie from paged control to remember the offset
      my ($resp) = $mesg->control(LDAP_CONTROL_PAGED) or last;

      $cookie = $resp->cookie or last;
      if ($cookie) {
        # set cookie in paged control
        $page->cookie($cookie);
      } else {
        # found all
        #writeDebug("ok, no more cookie");
        last;
      }
    } else {
      # one chunk ends here
      last;
    }
  }    # end reading pages

  #writeDebug("done reading pages");

  # clean up
  if ($cookie) {
    $page->cookie($cookie);
    $page->size(0);
    $this->search(%args);
  }

  # check for error
  return 0 if $gotError;

  # resolving WikiName clashes
  $nrRecords += $this->resolveWikiNameClashes($data, \%wikiNames, \%loginNames);

  # remember list of all user names
  $data->{WIKINAMES} = join(',', keys %wikiNames);
  $data->{LOGINNAMES} = join(',', keys %loginNames);

  writeDebug("got $nrRecords keys in cache");

  if ($this->{_topicUserMapping}) {
    foreach my $wikiName (sort values %{$this->{_topicUserMapping}}) {
      next if $wikiNames{$wikiName};
      #print STDERR "   * %USERSWEB%.$wikiName not found in LDAP\n";
      writeDebug("$wikiName not found in LDAP ");
    }
  }

  return 1;
}

=pod

---++ resolveWikiNameClashes($data, %wikiNames, %loginNames) -> $integer

if there have been name clashes those entry records
have not yet been added to the cache. They are kept until all clashes have been
found and a deterministic renaming scheme can be applied. Clashed WikiNames will be
enumerated - !WikiName1, !WikiName2, !WikiName3 etc - and finally added to the database.
The renaming is kept stable by sorting the dn entry of all clashed entries.

returns the number of additional entries that have been cached

=cut

sub resolveWikiNameClashes {
  my ($this, $data, $wikiNames, $loginNames) = @_;

  return 0 unless $this->{_wikiNameClaches};

  $data ||= $this->{data};

  my %suffixes = ();
  my $nrRecords = 0;
  my $refreshMode = $this->{_refreshMode} || 0;
  foreach my $item (sort { $a->{loginName} cmp $b->{loginName} } values %{$this->{_wikiNameClaches}}) {

    my $wikiName = $item->{wikiName};
    my $loginName = $item->{loginName};
    my $prevWikiName = ($refreshMode < 2) ? $this->getWikiNameOfLogin($loginName) : '';
    my $newWikiName;

    if ($prevWikiName) {
      writeDebug("found prevWikiName=$prevWikiName for $loginName");
      $newWikiName = $prevWikiName;
    } else {

      # search for a new wikiname
      my $prevLogin;
      do {
        $suffixes{$wikiName}++;
        $newWikiName = $wikiName . $suffixes{$wikiName};
        $prevLogin = $this->getLoginOfWikiName($newWikiName);
      } until (!$prevLogin || $prevLogin eq $loginName);
    }

    writeDebug("processing clash of loginName=$loginName on wikiName=$wikiName, resolves to newWikiName=$newWikiName");

    $this->cacheUserFromEntry($item->{entry}, $data, $wikiNames, $loginNames, $newWikiName);
    $nrRecords++;
  }

  delete $this->{_wikiNameClaches};

  return $nrRecords;
}

=pod

---++ refreshGroupsCache($data, $groupBase) -> $boolean

download all group records from the LDAP server

returns true if new records have been loaded

=cut

sub refreshGroupsCache {
  my ($this, $data, $groupBase) = @_;

  $data ||= $this->{data};

  # prepare search
  my %args = (
    filter => $this->{groupFilter},
    base => $groupBase,
    scope => $this->{groupScope},
    deref => "always",
    attrs => [$this->{groupAttribute}, $this->{memberAttribute}, $this->{innerGroupAttribute}, $this->{primaryGroupAttribute}],
  );

  # use the control LDAP extension only if a valid pageSize value has been provided
  my $page;
  my $cookie;
  if ($this->{pageSize} > 0) {
    require Net::LDAP::Control::Paged;
    $page = Net::LDAP::Control::Paged->new(size => $this->{pageSize});
    $args{control} = [$page];
  } else {
    #writeDebug("reading group from cache in one chunk");
  }

  # read pages
  my $nrRecords = 0;
  my %groupNames = map { $_ => 1 } @{$this->getGroupNames($data)};
  my $gotError = 0;

  $args{callback} = sub {
    my ($ldap, $entry) = @_;
    $this->cacheGroupFromEntry($entry, $data, \%groupNames) && $nrRecords++;
  };

  while (1) {

    # perform search
    my $mesg = $this->search(%args);
    unless ($mesg) {
      #writeDebug("oops, no result querying for groups");
      writeWarning("error refeshing the groups cache: " . $this->getError());
      last;
    }

    # only use cookies and pages if we are using this extension
    if ($page) {
      # get cookie from paged control to remember the offset
      my ($resp) = $mesg->control(LDAP_CONTROL_PAGED) or last;

      $cookie = $resp->cookie or last;
      if ($cookie) {
        # set cookie in paged control
        $page->cookie($cookie);
      } else {
        # found all
        #writeDebug("ok, no more cookie");
        last;
      }
    } else {
      last;
    }
  }    # end reading pages

  # clean up
  if ($cookie) {
    $page->cookie($cookie);
    $page->size(0);
    $this->search(%args);
  }

  # check for error
  return 0 if $gotError;

  # check for primary group membership
  if ($this->{_primaryGroup}) {
    foreach my $groupId (keys %{$this->{_primaryGroup}}) {
      my $groupName = $this->{_groupId}{$groupId};
      next unless $groupName;
      foreach my $member (keys %{$this->{_primaryGroup}{$groupId}}) {
        writeDebug("adding $member to its primary group $groupName");
        $this->{_groups}{$groupName}{$member} = 1;
      }
    }
  }

  # assert group members to data store
  foreach my $groupName (keys %{$this->{_groups}}) {

    my %members = ();
    foreach my $member (keys %{$this->{_groups}{$groupName}}) {

      # groups may store DNs to members instead of a memberUid, in this case we
      # have to lookup the corresponding loginAttribute
      if ($this->{memberIndirection}) {
        #writeDebug("following indirection for $member");
        my $memberName = $data->{"DN2U::$member"};
        if ($memberName) {
          $members{$memberName} = 1;
        } else {
          #writeWarning("oops, $member not found, but member of $groupName");
        }
      } else {
        $members{$member} = 1;
      }
    }

    $data->{"GROUPS::$groupName"} = join(',', sort keys %members);
    undef $this->{_groups}{$groupName};
  }
  undef $this->{_groups};

  # remember list of all groups
  $data->{GROUPS} = join(',', sort keys %groupNames);

  #writeDebug("got $nrRecords keys in cache");

  return 1;
}

=pod

---++ cacheUserFromEntry($entry, $data, $wikiNames, $loginNames, $wikiName) -> $boolean

store a user LDAP::Entry to our internal cache 

If the $wikiName parameter is given explicitly then this will be the name under which this record
will be cached.

returns true if new records have been created

=cut

sub cacheUserFromEntry {
  my ($this, $entry, $data, $wikiNames, $loginNames, $wikiName) = @_;

  #writeDebug("called cacheUserFromEntry()");

  $data ||= $this->{data};
  $wikiNames ||= {};
  $loginNames ||= {};

  my $dn = $entry->dn();

  # 1. get it
  my $loginName = $entry->get_value($this->{loginAttribute});
  $loginName =~ s/^\s+//o;
  $loginName =~ s/\s+$//o;
  unless ($loginName) {
    writeDebug("no loginName for $dn ... skipping");
    return 0;
  }
  $loginName = $this->fromLdapCharSet($loginName);

  # 2. normalize
  $loginName = $this->rewriteName($loginName, $this->{rewriteLoginNames});
  $loginName = lc($loginName) unless $this->{caseSensitiveLogin};
  $loginName = $this->normalizeLoginName($loginName) if $this->{normalizeLoginName};
  return 0 if $this->{excludeMap}{$loginName};

  # construct the wikiName
  if (!defined $wikiName && defined $this->{_topicUserMapping}) {
    $wikiName = $this->{_topicUserMapping}{$loginName};
    writeDebug("found wikiName for $loginName in topic mapping: $wikiName ... not reading ldap attributes")
      if defined $wikiName;
  }

  if (defined $wikiName) {
    #writeDebug("found explicit wikiName '$wikiName' for $loginName");
  } else {

    # 0. get previously used wikiName
    my $refreshMode = $this->{_refreshMode} || 0;
    my $prevWikiName = ($refreshMode < 2) ? $this->getWikiNameOfLogin($loginName) : '';

    # keep a wikiName once it has been computed
    if ($prevWikiName) {
      writeDebug("found prevWikiName=$prevWikiName for $loginName");
      $wikiName = $prevWikiName;
    } else {

      # 1. compute a new wikiName
      my @wikiName = ();
      foreach my $attr (@{$this->{wikiNameAttributes}}) {
        my $value = $entry->get_value($attr);
        next unless $value;
        $value =~ s/^\s+//o;
        $value =~ s/\s+$//o;
        $value = $this->fromLdapCharSet($value);
        #writeDebug("$attr=$value");
        push @wikiName, $value;
      }
      $wikiName = join(" ", @wikiName);

      unless ($wikiName) {
        #$wikiName = $loginName;
        #writeWarning("no WikiNameAttributes found for $dn ... deriving WikiName from LoginName: '$wikiName'");
        writeWarning("no WikiNameAttributes found for $dn ... ignoring");
        return 0;
      }

      # 2. rewrite
      $wikiName = $this->rewriteName($wikiName, $this->{rewriteWikiNames});

      # 3. normalize
      if ($this->{normalizeWikiName}) {
        $wikiName = $this->normalizeWikiName($wikiName);
      }

      # 4. aliasing based on WikiName
      my $alias = $this->{wikiNameAliases}{$wikiName};
      if ($alias) {
        writeDebug("using alias $alias for $wikiName");
        $wikiName = $alias;
      }

      # 5. check if this wikiName maps to a login already in use by another wikiName before
      my $prevLogin = $this->getLoginOfWikiName($wikiName) || '';
      if ($prevLogin && $prevLogin ne $loginName) {

        writeWarning("$loginName clashes with $prevLogin on wikiName $wikiName at $dn ... renaming later");
        $this->{_wikiNameClaches}{$loginName} = {
          entry => $entry,
          dn => $dn,
          wikiName => $wikiName,
          loginName => $loginName,
        };
        return 0;
      }

      # 6. check for name clashes within this transaction
      my $clashLogin = $this->getLoginOfWikiName($wikiName, $data);
      if (defined $clashLogin) {
        if ($loginName ne $clashLogin) {
          writeWarning("$loginName clashes with $clashLogin on wikiName $wikiName at $dn ... renaming later");
          $this->{_wikiNameClaches}{$loginName} = {
            entry => $entry,
            dn => $dn,
            wikiName => $wikiName,
            loginName => $loginName,
          };
        } else {
          # never reach: same dn found twice in same transaction
          writeWarning("$loginName found twice in ldap search at $dn ... ignoring second one");
        }
        return 0;
      }
    }
  }

  $wikiNames->{$wikiName} = 1;
  $loginNames->{$loginName} = 1;

  # get email addrs
  my $emails;
  @{$emails} = $entry->get_value($this->{mailAttribute});

  # get primary group
  if ($this->{primaryGroupAttribute}) {
    my $groupId = $entry->get_value($this->{primaryGroupAttribute});
    $this->{_primaryGroup}{$groupId}{$loginName} = 1 if $groupId;    # delayed
  }

  # store it
  writeDebug("adding wikiName='$wikiName', loginName='$loginName', dn='$dn'");
  $data->{"U2W::$loginName"} = $wikiName;
  $data->{"W2U::$wikiName"} = $loginName;
  $data->{"DN2U::$dn"} = $loginName;
  $data->{"U2DN::$loginName"} = $dn;
  $data->{"U2EMAIL::$loginName"} = join(',', @$emails);

  if ($emails) {
    foreach my $email (@$emails) {
      $email =~ s/^\s+//o;
      $email =~ s/\s+$//o;
      my $prevMapping = $data->{"EMAIL2U::$email"};
      my %emails = ();
      if ($prevMapping) {
        %emails = map { $_ => 1 } split(/\s*,\s*/, $prevMapping);
      }
      $emails{$loginName} = $email;
      $data->{"EMAIL2U::$email"} = join(',', sort keys %emails);
    }
  }

  my %groupNames = map { $_ => 1 } @{$this->getGroupNames($data)};

  foreach my $groupName (keys %groupNames) {
    if (defined $data->{"GROUP2UNCACHEDMEMBERSDN::$groupName"}) {
      my $dnList = Foswiki::Sandbox::untaintUnchecked($data->{"GROUP2UNCACHEDMEMBERSDN::$groupName"}) || '';
      my @membersDn = split(/\s*;\s*/, $dnList);

    LOOP: {
        foreach my $memberDn (@membersDn) {
          if ($memberDn eq $dn) {

            writeDebug("refreshing group $groupName to catch new members");
            removeGroupFromCache($this, $groupName, $data);
            checkCacheForGroupName($this, $groupName, $data);
            last LOOP;
          }
        }
      }
    }
  }
  return 1;
}

=pod

---++ cacheGroupFromEntry($entry, $data, $groupNames) -> $boolean

store a group LDAP::Entry to our internal cache 

returns true if new records have been created

=cut

sub cacheGroupFromEntry {
  my ($this, $entry, $data, $groupNames) = @_;

  $data ||= $this->{data};
  $groupNames ||= {};

  my $dn = $entry->dn();
  writeDebug("caching group for $dn");

  my $groupName = $entry->get_value($this->{groupAttribute});
  unless ($groupName) {
    writeDebug("no groupName for $dn ... skipping");
    return 0;
  }
  $groupName =~ s/^\s+//o;
  $groupName =~ s/\s+$//o;
  $groupName = $this->fromLdapCharSet($groupName);

  if ($this->{normalizeGroupName}) {
    $groupName = $this->normalizeWikiName($groupName);
  }
  return 0 if $this->{excludeMap}{$groupName};

  # rewrite groups
  $groupName = $this->rewriteName($groupName, $this->{rewriteGroups});

  if (!$this->{mergeGroups} && defined($groupNames->{$groupName})) {
    writeWarning("$dn clashes with group $groupNames->{$groupName} on $groupName");
    return 0;
  }

  my $loginName = $this->{caseSensitiveLogin} ? $groupName : lc($groupName);
  if (defined($data->{"U2W::$loginName"}) || defined($data->{"W2U::$groupName"})) {
    if ($this->{ignorePrivateGroups}) {
      writeDebug("ignoring private group $groupName as there is a login of that kind already");
      return 0;
    }
    my $groupSuffix = '';
    if ($this->{normalizeGroupName}) {
      $groupSuffix = 'Group';
    } else {
      $groupSuffix = '_group';
    }
    #writeWarning("group $dn clashes with user $groupName ... appending $groupSuffix");
    $groupName .= $groupSuffix;
  }

  # remember this
  $data->{"DN2U::$dn"} = $groupName;
  $data->{"U2DN::$groupName"} = $dn;

  # cache groupIds
  my $groupId = $entry->get_value($this->{primaryGroupAttribute});
  if ($groupId) {
    $this->{_groupId}{$groupId} = $groupName;
  }

  # fetch all members of this group
  my $memberVals = $entry->get_value($this->{memberAttribute}, alloptions => 1);
  my @members = (defined($memberVals) && exists($memberVals->{''})) ? @{$memberVals->{''}} : ();

  my $addMember = sub {
    my $member;
    while ($member = shift) {
      next unless defined $member;
      $member =~ s/^\s+//o;
      $member =~ s/\s+$//o;
      $this->{_groups}{$groupName}{$member} = 1;    # delay til all groups have been fetched
    }
  };

  if (@members) {
    $addMember->(@members);
  } else {

    # nothing? try AD's range=X-Y syntax
    while (1) {

      # "Parse" range
      my ($rangeEnd, $members);
      foreach my $k (keys %$memberVals) {
        next if $k !~ /^;range=(?:\d+)-(\*|\d+)$/o;
        ($rangeEnd, $members) = ($1, $memberVals->{$k});
        last;
      }
      last if !defined $rangeEnd;
      $addMember->(@$members);
      last if $rangeEnd eq '*';
      $rangeEnd++;

      # Apparently there are more members, so iterate
      # Apparently we need a dummy filter to make this work
      my $newRes = $this->search(filter => 'objectClass=*', base => $dn, scope => 'base', attrs => ["member;range=$rangeEnd-*"]);
      unless ($newRes) {
        writeWarning("error fetching more members for $dn: " . $this->getError());
        last;
      }

      my $newEntry = $newRes->pop_entry();
      if (!defined $newEntry) {
        writeWarning("no result when doing member;range=$rangeEnd-* search for $dn\n");
        last;
      }

      $memberVals = $newEntry->get_value($this->{memberAttribute}, alloptions => 1);
    }
  }

  # fetch all inner groups of this group
  foreach my $innerGroup ($entry->get_value($this->{innerGroupAttribute})) {
    next unless $innerGroup;
    $innerGroup =~ s/^\s+//o;
    $innerGroup =~ s/\s+$//o;
    # TODO: range=X-Y syntax not supported yet for innerGroups
    $this->{_groups}{$groupName}{$innerGroup} = 1;    # delay til all groups have been fetched
  }

  # store it
  writeDebug("adding groupName='$groupName', dn=$dn");

  $groupNames->{$groupName} = 1;

  return 1;
}

=pod 

---++ normalizeWikiName($name) -> $string

normalizes a string to form a proper <nop>WikiName

=cut

sub normalizeWikiName {
  my ($this, $name) = @_;

  $name = transliterate($name);

  my $wikiName = '';

  # first, try without forcing each part to be lowercase
  foreach my $part (split(/[^$Foswiki::regex{mixedAlphaNum}]/, $name)) {
    $wikiName .= ucfirst($part);
  }

  # if it isn't a valid WikiWord and there's no homepage of that name yet, then try more agressively to
  # create a proper WikiName
  if (!Foswiki::Func::isValidWikiWord($wikiName) && !Foswiki::Func::topicExists($Foswiki::cfg{UsersWebName}, $wikiName)) {
    $wikiName = '';
    foreach my $part (split(/[^$Foswiki::regex{mixedAlphaNum}]/, $name)) {
      $wikiName .= ucfirst(lc($part));
    }
  }

  return $wikiName;
}

=pod 

---++ normalizeLoginName($name) -> $string

normalizes a string to form a proper login

=cut

sub normalizeLoginName {
  my ($this, $name) = @_;

  $name =~ s/@.*$//o;    # remove REALM

  $name = transliterate($name);
  $name =~ s/[^$Foswiki::cfg{LoginNameFilterIn}]//;

  return $name;
}

=pod

---++ rewriteName($in, $rules) -> $out

rewrites a name based on a set of rewrite rules

=cut

sub rewriteName {
  my ($this, $in, $rules) = @_;

  return $in unless $rules;

  my $out = $in;

  while (my ($pattern,$subst) = each %$rules) {
    if ($out =~ /^(?:$pattern)$/) {
      my $arg1 = $1;
      my $arg2 = $2;
      my $arg3 = $3;
      my $arg4 = $4;
      my $arg5 = $5;
      $arg1 = '' unless defined $arg1;
      $arg2 = '' unless defined $arg2;
      $arg3 = '' unless defined $arg3;
      $arg4 = '' unless defined $arg4;
      $subst =~ s/\$1/$arg1/g;
      $subst =~ s/\$2/$arg2/g;
      $subst =~ s/\$3/$arg3/g;
      $subst =~ s/\$4/$arg4/g;
      $subst =~ s/\$5/$arg5/g;
      $out = $subst;
      writeDebug("rewriting '$in' to '$out' using rule $pattern");
      last;
    }
  }

  return $out;
}

=pod

---++ transliterate($string) -> $string

transliterate some essential utf8 chars to a common replacement
in latin1 encoding. the list above is not exhaustive.

use http://www.ltg.ed.ac.uk/~richard/utf-8.html to add more recodings

=cut

sub transliterate {
  my $string = shift;

  if ($Foswiki::cfg{Site}{CharSet} =~ /^utf-?8$/i) {
    $string =~ s/\xc3\xa0/a/go;    # a grave
    $string =~ s/\xc3\xa1/a/go;    # a acute
    $string =~ s/\xc3\xa2/a/go;    # a circumflex
    $string =~ s/\xc3\xa3/a/go;    # a tilde
    $string =~ s/\xc3\xa4/ae/go;   # a uml
    $string =~ s/\xc3\xa5/a/go;    # a ring above
    $string =~ s/\xc3\xa6/ae/go;   # ae
    $string =~ s/\xc4\x85/a/go;    # a ogonek

    $string =~ s/\xc3\x80/A/go;    # A grave
    $string =~ s/\xc3\x81/A/go;    # A acute
    $string =~ s/\xc3\x82/A/go;    # A circumflex
    $string =~ s/\xc3\x83/A/go;    # A tilde
    $string =~ s/\xc3\x84/Ae/go;   # A uml
    $string =~ s/\xc3\x85/A/go;    # A ring above
    $string =~ s/\xc3\x86/AE/go;   # AE
    $string =~ s/\xc4\x84/A/go;    # A ogonek

    $string =~ s/\xc3\xa7/c/go;    # c cedille
    $string =~ s/\xc4\x87/c/go;    # c acute
    $string =~ s/\xc4\x8d/c/go;    # c caron
    $string =~ s/\xc3\x87/C/go;    # C cedille
    $string =~ s/\xc4\x86/C/go;    # C acute
    $string =~ s/\xc4\x8c/C/go;    # C caron

    $string =~ s/\xc4\x8f/d/go;    # d caron
    $string =~ s/\xc4\x8e/D/go;    # D caron

    $string =~ s/\xc3\xa8/e/go;    # e grave
    $string =~ s/\xc3\xa9/e/go;    # e acute
    $string =~ s/\xc3\xaa/e/go;    # e circumflex
    $string =~ s/\xc3\xab/e/go;    # e uml
    $string =~ s/\xc4\x9b/e/go;    # e caron

    $string =~ s/\xc4\x99/e/go;    # e ogonek
    $string =~ s/\xc4\x98/E/go;    # E ogonek
    $string =~ s/\xc4\x9a/E/go;    # E caron

    $string =~ s/\xc3\xb2/o/go;    # o grave
    $string =~ s/\xc3\xb3/o/go;    # o acute
    $string =~ s/\xc3\xb4/o/go;    # o circumflex
    $string =~ s/\xc3\xb5/o/go;    # o tilde
    $string =~ s/\xc3\xb6/oe/go;   # o uml
    $string =~ s/\xc3\xb8/o/go;    # o stroke

    $string =~ s/\xc3\xb3/o/go;    # o acute
    $string =~ s/\xc3\x93/O/go;    # O acute

    $string =~ s/\xc3\x92/O/go;    # O grave
    $string =~ s/\xc3\x93/O/go;    # O acute
    $string =~ s/\xc3\x94/O/go;    # O circumflex
    $string =~ s/\xc3\x95/O/go;    # O tilde
    $string =~ s/\xc3\x96/Oe/go;   # O uml

    $string =~ s/\xc3\xb9/u/go;    # u grave
    $string =~ s/\xc3\xba/u/go;    # u acute
    $string =~ s/\xc3\xbb/u/go;    # u circumflex
    $string =~ s/\xc3\xbc/ue/go;   # u uml
    $string =~ s/\xc5\xaf/u/go;    # u ring above

    $string =~ s/\xc3\x99/U/go;    # U grave
    $string =~ s/\xc3\x9a/U/go;    # U acute
    $string =~ s/\xc3\x9b/U/go;    # U circumflex
    $string =~ s/\xc3\x9c/Ue/go;   # U uml
    $string =~ s/\xc5\xae/U/go;    # U ring above

    $string =~ s/\xc5\x99/r/go;    # r caron
    $string =~ s/\xc5\x98/R/go;    # R caron

    $string =~ s/\xc3\x9f/ss/go;   # sharp s
    $string =~ s/\xc5\x9b/s/go;    # s acute
    $string =~ s/\xc5\xa1/s/go;    # s caron
    $string =~ s/\xc5\x9a/S/go;    # S acute
    $string =~ s/\xc5\xa0/S/go;    # S caron

    $string =~ s/\xc5\xa5/t/go;    # t caron
    $string =~ s/\xc5\xa4/T/go;    # T caron

    $string =~ s/\xc3\xb1/n/go;    # n tilde
    $string =~ s/\xc5\x84/n/go;    # n acute
    $string =~ s/\xc5\x88/n/go;    # n caron
    $string =~ s/\xc5\x83/N/go;    # N acute
    $string =~ s/\xc5\x87/N/go;    # N caron

    $string =~ s/\xc3\xbe/y/go;    # y acute
    $string =~ s/\xc3\xbf/y/go;    # y uml

    $string =~ s/\xc3\xac/i/go;    # i grave
    $string =~ s/\xc3\xab/i/go;    # i acute
    $string =~ s/\xc3\xac/i/go;    # i circumflex
    $string =~ s/\xc3\xad/i/go;    # i uml

    $string =~ s/\xc5\x82/l/go;    # l stroke
    $string =~ s/\xc4\xbe/l/go;    # l caron
    $string =~ s/\xc5\x81/L/go;    # L stroke
    $string =~ s/\xc4\xbd/L/go;    # L caron

    $string =~ s/\xc5\xba/z/go;    # z acute
    $string =~ s/\xc5\xb9/Z/go;    # Z acute
    $string =~ s/\xc5\xbc/z/go;    # z dot
    $string =~ s/\xc5\xbb/Z/go;    # Z dot
    $string =~ s/\xc5\xbe/z/go;    # z caron
    $string =~ s/\xc5\xbd/Z/go;    # Z caron
  } else {
    $string =~ s/\xe0/a/go;        # a grave
    $string =~ s/\xe1/a/go;        # a acute
    $string =~ s/\xe2/a/go;        # a circumflex
    $string =~ s/\xe3/a/go;        # a tilde
    $string =~ s/\xe4/ae/go;       # a uml
    $string =~ s/\xe5/a/go;        # a ring above
    $string =~ s/\xe6/ae/go;       # ae
    $string =~ s/\x01\x05/a/go;    # a ogonek

    $string =~ s/\xc0/A/go;        # A grave
    $string =~ s/\xc1/A/go;        # A acute
    $string =~ s/\xc2/A/go;        # A circumflex
    $string =~ s/\xc3/A/go;        # A tilde
    $string =~ s/\xc4/Ae/go;       # A uml
    $string =~ s/\xc5/A/go;        # A ring above
    $string =~ s/\xc6/AE/go;       # AE
    $string =~ s/\x01\x04/A/go;    # A ogonek

    $string =~ s/\xe7/c/go;        # c cedille
    $string =~ s/\x01\x07/C/go;    # c acute
    $string =~ s/\xc7/C/go;        # C cedille
    $string =~ s/\x01\x06/c/go;    # C acute

    $string =~ s/\xe8/e/go;        # e grave
    $string =~ s/\xe9/e/go;        # e acute
    $string =~ s/\xea/e/go;        # e circumflex
    $string =~ s/\xeb/e/go;        # e uml
    $string =~ s/\x01\x19/e/go;    # e ogonek
    $string =~ s/\xc4\x18/E/go;    # E ogonek

    $string =~ s/\xf2/o/go;        # o grave
    $string =~ s/\xf3/o/go;        # o acute
    $string =~ s/\xf4/o/go;        # o circumflex
    $string =~ s/\xf5/o/go;        # o tilde
    $string =~ s/\xf6/oe/go;       # o uml
    $string =~ s/\xf8/oe/go;       # o stroke

    $string =~ s/\xd3/o/go;        # o acute
    $string =~ s/\xf3/O/go;        # O acute

    $string =~ s/\xd2/O/go;        # O grave
    $string =~ s/\xd3/O/go;        # O acute
    $string =~ s/\xd4/O/go;        # O circumflex
    $string =~ s/\xd5/O/go;        # O tilde
    $string =~ s/\xd6/Oe/go;       # O uml

    $string =~ s/\xf9/u/go;        # u grave
    $string =~ s/\xfa/u/go;        # u acute
    $string =~ s/\xfb/u/go;        # u circumflex
    $string =~ s/\xfc/ue/go;       # u uml

    $string =~ s/\xd9/U/go;        # U grave
    $string =~ s/\xda/U/go;        # U acute
    $string =~ s/\xdb/U/go;        # U circumflex
    $string =~ s/\xdc/Ue/go;       # U uml

    $string =~ s/\xdf/ss/go;       # sharp s
    $string =~ s/\x01\x5b/s/go;    # s acute
    $string =~ s/\x01\x5a/S/go;    # S acute

    $string =~ s/\xf1/n/go;        # n tilde
    $string =~ s/\x01\x44/n/go;    # n acute
    $string =~ s/\x01\x43/N/go;    # N acute

    $string =~ s/\xfe/y/go;        # y acute
    $string =~ s/\xff/y/go;        # y uml

    $string =~ s/\xec/i/go;        # i grave
    $string =~ s/\xed/i/go;        # i acute
    $string =~ s/\xee/i/go;        # i circumflex
    $string =~ s/\xef/i/go;        # i uml

    $string =~ s/\x01\x42/l/go;    # l stroke
    $string =~ s/\x01\x41/L/go;    # L stroke

    $string =~ s/\x01\x7a/z/go;    # z acute
    $string =~ s/\x01\x79/Z/go;    # Z acute
    $string =~ s/\x01\x7c/z/go;    # z dot
    $string =~ s/\x01\x7b/Z/go;    # Z dot
  }

  return $string;
}

=pod

---++ getGroupNames($data) -> @array

Returns a list of known group names.

=cut

sub getGroupNames {
  my ($this, $data) = @_;

  #writeDebug("called getGroupNames()");

  $data ||= $this->{data};

  my $groupNames = Foswiki::Sandbox::untaintUnchecked($data->{GROUPS}) || '';
  my @groupNames = split(/\s*,\s*/, $groupNames);

  return \@groupNames;
}

=pod

---++ isGroup($wikiName, $data) -> $boolean

check if a given user is an ldap group actually

=cut

sub isGroup {
  my ($this, $wikiName, $data) = @_;

  #writeDebug("called isGroup($wikiName)");
  $data ||= $this->{data};

  return undef if $wikiName =~ /^BaseUserMapping/;
  return undef if $this->{excludeMap}{$wikiName};
  return 1 if defined($data->{"GROUPS::$wikiName"});
  return 0 if defined($data->{"W2U::$wikiName"});

  my $loginName = $this->{caseSensitiveLogin} ? $wikiName : lc($wikiName);
  return 0 if defined($data->{"U2W::$loginName"});

  unless ($this->{preCache}) {
    $this->checkCacheForGroupName($wikiName, $data);
    return 1 if defined($data->{"GROUPS::$wikiName"});
  }

  return undef;
}

=pod

---++ getEmails($loginName, $data) -> @emails

fetch emails from LDAP

=cut

sub getEmails {
  my ($this, $loginName, $data) = @_;

  $loginName = lc($loginName) unless $this->{caseSensitiveLogin};
  $data ||= $this->{data};

  $this->checkCacheForLoginName($loginName, $data) unless $this->{preCache};

  my $emails = Foswiki::Sandbox::untaintUnchecked($data->{"U2EMAIL::" . $loginName}) || '';
  my @emails = split(/\s*,\s*/, $emails);
  return \@emails;
}

=pod

---++ getLoginOfEmail($email, $data) \@users

get all users matching a given email address

=cut

sub getLoginOfEmail {
  my ($this, $email, $data) = @_;

  $data ||= $this->{data};

  my $loginNames = Foswiki::Sandbox::untaintUnchecked($data->{"EMAIL2U::" . $email}) || '';
  my @loginNames = split(/\s*,\s*/, $loginNames);
  return \@loginNames;

}

=pod

---++ getGroupMembers($groupName, $data) -> \@array

=cut

sub getGroupMembers {
  my ($this, $groupName, $data) = @_;
  return undef if $this->{excludeMap}{$groupName};

  #writeDebug("called getGroupMembers $groupName");

  $data ||= $this->{data};

  unless ($this->{preCache}) {

    # Make sure that the group is in the cache. This will cause the addition of the group to the cache if it exists in LDAP
    return undef unless $this->isGroup($groupName, $data);
  }

  my $members = Foswiki::Sandbox::untaintUnchecked($data->{"GROUPS::$groupName"}) || '';
  my @members = split(/\s*,\s*/, $members);

  return \@members;
}

=pod

---++ isGroupMember($loginName, $groupName, $data) -> $boolean

check if a given user is member of an ldap group

=cut

sub isGroupMember {
  my ($this, $loginName, $groupName, $data) = @_;

  $data ||= $this->{data};

  unless ($this->{preCache}) {
    # We need to make sure both user and group are in the cache. These calls will trigger LDAP lookups if appropriate.
    return 0 unless $this->checkCacheForLoginName($loginName, $data);
    return 0 unless $this->isGroup($groupName, $data);
  }

  my $members = $data->{"GROUPS::$groupName"} || '';
  return ($members =~ /\b$loginName\b/) ? 1 : 0;
}

=pod 

---++ getWikiNameOfLogin($loginName, $data) -> $wikiName

returns the wikiName of a loginName or undef if it does not exist

=cut

sub getWikiNameOfLogin {
  my ($this, $loginName, $data) = @_;

  #writeDebug("called getWikiNameOfLogin($loginName)");

  $loginName = lc($loginName) unless $this->{caseSensitiveLogin};
  $data ||= $this->{data};

  unless ($this->{preCache}) {
    # Make sure the user has been retreived from LDAP
    $this->checkCacheForLoginName($loginName, $data);
  }

  return Foswiki::Sandbox::untaintUnchecked($data->{"U2W::$loginName"});
}

=pod 

---++ getLoginOfWikiName($wikiName, $data) -> $loginName

returns the loginNAme of a wikiName or undef if it does not exist

=cut

sub getLoginOfWikiName {
  my ($this, $wikiName, $data) = @_;

  $data ||= $this->{data};

  my $loginName = Foswiki::Sandbox::untaintUnchecked($data->{"W2U::$wikiName"});

  unless ($loginName) {
    my $alias = $this->{wikiNameAliases}{$wikiName};
    $loginName = Foswiki::Sandbox::untaintUnchecked($data->{"W2U::$alias"})
      if defined($alias);
  }

  return $loginName;
}

=pod 

---++ getAllWikiNames($data) -> \@array

returns a list of all known wikiNames

=cut

sub getAllWikiNames {
  my ($this, $data) = shift;

  $data ||= $this->{data};

  my $wikiNames = Foswiki::Sandbox::untaintUnchecked($data->{WIKINAMES}) || '';
  my @wikiNames = split(/\s*,\s*/, $wikiNames);
  return \@wikiNames;
}

=pod 

---++ getAllLoginNames($data) -> \@array

returns a list of all known loginNames

=cut

sub getAllLoginNames {
  my ($this, $data) = @_;

  $data ||= $this->{data};

  my $loginNames = Foswiki::Sandbox::untaintUnchecked($data->{LOGINNAMES}) || '';
  my @loginNames = split(/\s*,\s*/, $loginNames);
  return \@loginNames;
}

=pod 

---++ getDnOfLogin($loginName, $data) -> $dn

returns the Distinguished Name of the LDAP record of the given name

=cut

sub getDnOfLogin {
  my ($this, $loginName, $data) = @_;

  return unless $loginName;

  $loginName = lc($loginName) unless $this->{caseSensitiveLogin};
  $data ||= $this->{data};

  return Foswiki::Sandbox::untaintUnchecked($data->{"U2DN::$loginName"});
}

=pod 

---++ getDnOfWikiName($wikiName, $data) -> $dn

returns the Distinguished Name of the LDAP record of the given name

=cut

sub getDnOfWikiName {
  my ($this, $wikiName, $data) = @_;

  return unless $wikiName;

  $data ||= $this->{data};

  my $loginName = Foswiki::Sandbox::untaintUnchecked($data->{"W2U::$wikiName"});
  return unless $loginName;

  return Foswiki::Sandbox::untaintUnchecked($data->{"U2DN::$loginName"});
}

=pod 

---++ getWikiNameOfDn($dn, $data) -> $wikiName

returns the wikiName used by a given Distinguished Name; reverse of getDnOfWikiName()

=cut

sub getWikiNameOfDn {
  my ($this, $dn, $data) = @_;

  return unless $dn;

  $data ||= $this->{data};

  my $loginName = Foswiki::Sandbox::untaintUnchecked($data->{"DN2U::$dn"});
  return unless $loginName;

  return Foswiki::Sandbox::untaintUnchecked($data->{"U2W::$loginName"});
}

=pod 

---++ changePassword($loginName, $newPassword, $oldPassword) -> $boolean

=cut

sub changePassword {
  my ($this, $loginName, $newPassword, $oldPassword) = @_;

  return undef
    unless $this->{allowChangePassword} && defined($oldPassword) && $oldPassword ne '1';

  my $dn = $this->getDnOfLogin($loginName);
  return undef unless $dn;

  return undef unless $this->connect($dn, $oldPassword);

  my $msg = $this->{ldap}->set_password(
    oldpasswd => $oldPassword,
    newpasswd => $newPassword
  );

  my $errorCode = $this->checkError($msg);

  if ($errorCode != LDAP_SUCCESS) {
    writeWarning("error in changePassword: " . $this->getError());
    return undef;
  }

  return 1;
}

=pod

---++ checkCacheForLoginName($loginName, $data) -> $boolean

grant that the current loginName is cached. If not, it will download the LDAP
record for this specific user and update the LDAP cache with this single record.

This happens when the user is authenticated externally, e.g. using apache's
mod_authz_ldap or some other SSO, and the internal cache 
is not yet updated. It is completely updated regularly on a specific time
interval (default every 24h). See the LdapContrib settings.

=cut

sub checkCacheForLoginName {
  my ($this, $loginName, $data) = @_;

  return 0 unless ($loginName);

  writeDebug("called checkCacheForLoginName($loginName)");

  $loginName = lc($loginName) unless $this->{caseSensitiveLogin};
  $data ||= $this->{data};

  return 1 if $data->{"U2W::$loginName"};

  # If we are not in precache mode we need to check if the user has not yet been unsuccessfully lookedup in LDAP
  # To avoid excessive useless queries for the same non existing user
  unless ($this->{preCache}) {
    if ($this->isUnknownUser($loginName, $data)) {
      return 0;
    }
  }

  # update cache selectively
  writeDebug("$loginName is unknown, need to refresh part of the ldap cache");

  my $entry = $this->getAccount($loginName);

  # Release read lock and re-tie with write lock to get exclusive access
  # while we're altering the cache
  $this->untieCache();
  $this->tieCache('write');

  my $result = 0;

  unless ($entry) {
    writeWarning("oops, no result looking for user $loginName in LDAP");
    $this->addIgnoredUser($loginName, $data);
  } else {
    # merge this user record

    my %wikiNames = map { $_ => 1 } @{$this->getAllWikiNames($data)};
    my %loginNames = map { $_ => 1 } @{$this->getAllLoginNames($data)};
    $this->cacheUserFromEntry($entry, $data, \%wikiNames, \%loginNames);
    $this->resolveWikiNameClashes($data, \%wikiNames, \%loginNames); # see Item12670

    $data->{WIKINAMES} = join(',', keys %wikiNames);
    $data->{LOGINNAMES} = join(',', keys %loginNames);

    $result = 1;
  }

  # Release write lock and re-tie with read lock 
  $this->untieCache();
  $this->tieCache('read');

  return $result;
}

=pod

---++ removeGroupFromCache($groupName, $data) -> $boolean

Remove a group from the cache

=cut

sub removeGroupFromCache {
  my ($this, $groupName, $data) = @_;

  return 0 unless defined $groupName;

  $data ||= $this->{data};

  my %groupNames = map { $_ => 1 } @{$this->getGroupNames($data)};
  my $dn = $this->getDnOfLogin($groupName, $data);

  delete $groupNames{$groupName};
  delete $data->{"GROUPS::$groupName"};
  delete $data->{"GROUP2UNCACHEDMEMBERSDN::$groupName"};
  delete $data->{"U2DN::$groupName"};
  delete $data->{"DN2U::$dn"} if defined $dn;

  $data->{GROUPS} = join(',', keys %groupNames);

  return 1;
}

=pod

---++ removeUserFromCache($wikiName, $data) -> $boolean

removes a wikiName from the cache

=cut

sub removeUserFromCache {
  my ($this, $wikiName, $data) = @_;

  return 0 unless defined $wikiName;

  $data ||= $this->{data};

  my %wikiNames = map { $_ => 1 } @{$this->getAllWikiNames($data)};
  my %loginNames = map { $_ => 1 } @{$this->getAllLoginNames($data)};
  my $loginName = $this->getLoginOfWikiName($wikiName);
  my $dn = $this->getDnOfLogin($loginName, $data);

  # Release read lock and re-tie with write lock to get exclusive access
  # while we're altering the cache
  $this->untieCache();
  $this->tieCache('write');

  delete $loginNames{$loginName};
  delete $wikiNames{$wikiName};
  delete $data->{"U2W::$loginName"};
  delete $data->{"W2U::$wikiName"};
  delete $data->{"DN2U::$dn"};
  delete $data->{"U2DN::$loginName"};
  delete $data->{"U2EMAIL::$loginName"};

  foreach my $email (@{$this->getEmails($loginName, $data)}) {
    my %emails = map { $_ => 1 } split(/\s*,\s*/, $data->{"EMAIL2U::$email"});
    delete $emails{$loginName};
    $data->{"EMAIL2U::$email"} = join(',', sort keys %emails);
  }

  $data->{LOGINNAMES} = join(',', keys %loginNames);
  $data->{WIKINAMES} = join(',', keys %wikiNames);

  # Release write lock and re-tie with read lock 
  $this->untieCache();
  $this->tieCache('read');
}

=begin text

---++ renameWikiName($loginName, $oldWikiName, $newWikiName) 

assigns the new !WikiName to the given login

=cut

sub renameWikiName {
  my ($this, $loginName, $oldWikiName, $newWikiName, $data) = @_;

  $data ||= $this->{data};

  writeDebug("renameWikiName($loginName, $oldWikiName, $newWikiName)");

  if (defined $data->{"W2U::$oldWikiName"}) {
    delete $data->{"W2U::$oldWikiName"};

    $data->{"U2W::$loginName"} = $newWikiName;
    $data->{"W2U::$newWikiName"} = $loginName;
    return 1;
  }

  #writeWarning("oldWikiName=$oldWikiName not found in cache");
  return 0;
}

=pod 

---++ addIgnoredUser($loginName, $data) -> \@array

Insert a new user in the list of unknown users that should not be lookedup in LDAP

=cut

sub addIgnoredUser {
  my ($this, $loginName, $data) = @_;

  $data ||= $this->{data};

  $data->{UNKWNUSERS} .= ',' . $loginName
    unless $this->isUnknownUser($loginName, $data);
}

=pod 

---++++ isUnknownUser($loginName, $data) -> $boolean

returns 1 if $loginName is an unknown user that should not be relookedup in LDAP

=cut

sub isUnknownUser {
  my ($this, $loginName, $data) = @_;

  $data ||= $this->{data};

  my $names = Foswiki::Sandbox::untaintUnchecked($data->{UNKWNUSERS}) || '';
  return $names =~ /\b$loginName\b/;
}

=pod 

---++ addIgnoredGroup($groupName, $data) -> \@array

Insert a new group in the list of unknown groups that should not be lookedup in LDAP

=cut

sub addIgnoredGroup {
  my ($this, $groupName, $data) = @_;

  $data ||= $this->{data};

  $data->{UNKWNGROUPS} .= ',' . $groupName
    unless $this->isUnknownGroup($groupName, $data);
}

=pod 

---++++ isUnknownGroup($groupName, $data) -> $boolean

returns 1 if $groupName is an unknown groups that should not be relookedup in LDAP

=cut

sub isUnknownGroup {
  my ($this, $groupName, $data) = @_;

  $data ||= $this->{data};

  my $wikiNames = Foswiki::Sandbox::untaintUnchecked($data->{UNKWNGROUPS}) || '';
  return $wikiNames =~ /\b$groupName\b/;
}

=pod

---++ checkCacheForLoginName($groupName, $data) -> $boolean

grant that the current groupName is cached. If not, it will download the LDAP
record for this specific group and its subgroups and update the LDAP cache with the retreived records.

This happens when the precache mode is off. See the LdapContrib settings.

=cut

sub checkCacheForGroupName {
  my ($this, $groupName, $data) = @_;

  #writeDebug("called checkCacheForGroupName($groupName)");

  $data ||= $this->{data};

  # Skip lookup if group was already not found in LDAP since last cache expiration
  unless ($this->{preCache}) {
    if ($this->isUnknownGroup($groupName, $data)) {
      return 0;
    }
  }

  # update cache selectively
  writeDebug("group $groupName is unknown, need to refresh part of the ldap cache");

  my $entry = $this->getGroup($groupName);

  # Release read lock and re-tie with write lock to get exclusive access
  # while we're altering the cache
  $this->untieCache();
  $this->tieCache('write');

  my $result = 0;
  unless ($entry) {

    writeWarning("oops, no result looking for group $groupName in LDAP");
    $this->addIgnoredGroup($groupName, $data);

  } else {

    # merge this group record
    my %groupNames = map { $_ => 1 } @{$this->getGroupNames($data)};

    $this->cacheGroupFromEntry($entry, $data, \%groupNames);

    # remember list of all groups
    $data->{GROUPS} = join(',', sort keys %groupNames);

    # check for primary group membership
    if ($this->{_primaryGroup}) {
      foreach my $groupId (keys %{$this->{_primaryGroup}}) {
        my $currentGroupName = $this->{_groupId}{$groupId};

        if (defined $currentGroupName && $groupName eq $currentGroupName) {
          foreach my $member (keys %{$this->{_primaryGroup}{$groupId}}) {

            #writeDebug("adding $member to its primary group $currentGroupName");
            $this->{_groups}{$currentGroupName}{$member} = 1;
          }
        }
      }
    }

    # assert group members to data store
    my %members = ();
    my %uncachedMembersDn = ();

    foreach my $member (keys %{$this->{_groups}{$groupName}}) {

      # groups may store DNs to members instead of a memberUid, in this case we
      # have to lookup the corresponding loginAttribute
      if ($this->{memberIndirection}) {

        #writeDebug("following indirection for $member");

        my $memberName = $data->{"DN2U::$member"};
        if ($memberName) {
          $members{$memberName} = 1;
        } else {

          # Recursive check for groups when not in precache mode
          if (!$this->{preCache} && $member =~ /$this->{groupBase}/i) {
            my $innerGroupName = $member;
            $innerGroupName =~ s/$this->{groupBase}//o;
            $innerGroupName =~ s/$this->{groupAttribute}=//oi;
            $innerGroupName =~ s/^,+//o;
            $innerGroupName =~ ($this->{UserScope} eq 'sub' || $this->{GroupAttribute} eq 'sub') ? s/,.*$//o : s/,+$//o;

            # Smell: this may not be reliable and may work only with membersindirection. TO CHECK
            if ($innerGroupName ne "" && $this->isGroup($innerGroupName, $data)) {
              $members{$innerGroupName} = 1;
              next;
            }
          }

          #writeWarning("oops, $member not found, but member of $groupName");
          $uncachedMembersDn{$member} = 1;
        }
      } else {
        $members{$member} = 1;
      }
    }

    $data->{"GROUPS::$groupName"} = join(',', sort keys %members);

    if ($this->{memberIndirection}) {
      $data->{"GROUP2UNCACHEDMEMBERSDN::$groupName"} = join(';', keys %uncachedMembersDn);
    }

    undef $this->{_groups}{$groupName};
    undef $this->{_groups};

    $result = 1;
  }

  # Release write lock and re-tie with read lock 
  $this->untieCache();
  $this->tieCache('read');

  return $result;
}

=pod

---++ getGroup($groupName) -> Net::LDAP::Entry object

Fetches a group entry from the database and returns a Net::LDAP::Entry
object on success and undef otherwise. Note, the group name is match against
the attribute defined in $ldap->{groupAttribute}. Account records are 
search using $ldap->{groupFilter} in the subtree defined by $ldap->{groupBase}.

=cut

sub getGroup {
  my ($this, $groupName) = @_;

  #writeDebug("called getGroup($groupName)");
  return undef if $this->{excludeMap}{$groupName};

  my $filter = '(&(' . $this->{groupFilter} . ')(' . $this->{groupAttribute} . '=' . $groupName . '))';
  my $entry;

  foreach my $groupBase (@{$this->{groupBase}}) {
    my $msg = $this->search(
      filter => $filter,
      base => $groupBase,
      callback => sub {
        my (undef, $result) = @_;
        return unless defined $result;
        $entry = $result;
      }
    );
    return $entry if $entry;
  }

  $this->{error} = 'Group invalid';
  #writeDebug($this->{error});

  return;
}

=pod

---++ fromLdapCharSet($string) -> $string

decode strings coming from ldap 

=cut

sub fromLdapCharSet {
  my ($this, $string) = @_;

  my $ldapCharSet = $Foswiki::cfg{Ldap}{CharSet} || 'utf-8';

  return Encode::decode($ldapCharSet, $string);
}

=begin text

---++ toLdapCharSet($string) -> $string

encode strings coming from the site to be used talking to the ldap directory

=cut

sub toSiteCharSet {
  my ($this, $string) = @_;

  my $ldapCharSet = $Foswiki::cfg{Ldap}{CharSet} || 'utf-8';

  return Encode::encode($ldapCharSet, $string);
}

=begin TML

---++ ObjectMethod loadSession()

Load the session, sanitize the login name and make sure its user information are already
cached.

=cut

sub loadSession {
  my ($this, $authUser) = @_;

  # process authUser login name
  if (defined $authUser) {

    my $origAuthUser = $authUser;

    $authUser =~ s/^\s+//o;
    $authUser =~ s/\s+$//o;
    $authUser = $this->fromLdapCharSet($authUser);

    $authUser = lc($authUser) unless $this->{caseSensitiveLogin};
    $authUser = $this->normalizeLoginName($authUser) if $this->{normalizeLoginName};

    #print STDERR "origAuthUser=$origAuthUser, authUser=$authUser\n";

    if ($this->{excludeMap}{$authUser}) {
      $authUser = $origAuthUser; 
    } else {
      $this->checkCacheForLoginName($authUser);
    }
  }

  return $authUser;
}

1;

