# News::Collabra
# Administrative access to Collabra's access controls.
#
# $Id: Collabra.pm,v 0.3 2001/01/30 07:44:32 nate Exp $

=head1 News::Collabra -- Access to Collabra administrative functions

=head2 Synopsis

	# Create an administrator object
	my $admin = new News::Collabra('username', 'password',
		'myhost.mydomain.com', 'news-myhost', '1234');

	# Administrate newsgroups
	my $result = $admin->add_newsgroup('junk.test',
		'Testing newsgroup','A newsgroup for testing Collabra.pm');
	my $result = $admin->remove_newsgroup('junk.test');
	my $result = $admin->delete_all_articles('junk.test');
	my $result = $admin->get_ng_acls('junk.test');
	my $result = $admin->add_ng_acl('junk.test','nbailey','manager');
	my $result = $admin->get_properties('junk.test');
	my $result = $admin->set_properties('junk.test',
		'Post your tests here!','A test group for FL&T');

	# Administrate the server
	my $result = $admin->server_start;
	my $result = $admin->server_status;
	my $result = $admin->server_stop;

=head2 Description

This module provides an incomplete but growing implementation of a
Collabra admin interface.  Collabra administrative functions are based
on HTTP, not NNTP, so most of these functions use LWP::UserAgent,
rather than News::NNTP/News::NNTPClient.

For the uninitiated, Collabra is iPlanet's hacked over version of
inews, with LDAP-based access control.  Unfortunately, this otherwise
fairly good idea is clouded by a crufty JavaScript interface.  This
module is intended to provide direct access to the functions, to save
administrators the pain of the JavaScript interface.

=over 4

=cut
 
package News::Collabra;
use strict;
require 5.004;
 
use vars qw($VERSION);
$VERSION = "0.03";      # $Date: 2001/01/30 07:44:32 $
 
use IO::Socket;
use URI::Escape;
use News::NNTPClient;
use Carp;
# Nasty -- should be a part of the object, not static variables
my $host = 'localhost';
my $alias = 'newsserver';
my $port = '1234';

# Nasty -- should be a part of the object, not a static variable
use LWP::UserAgent;
my $ua = new LWP::UserAgent;
$ua->agent("News::Collabra/$VERSION " . $ua->agent);

=item new($username, $password, $host, $alias, $port)

Creates a C<News::Collabra> object given the necessary details.  This
method does not currently test that the username/password combination
is valid, but it may soon.  Watch this space.

=cut

sub new
{
	my ($clazz, $uid, $passwd, $host, $alias, $port) = @_;

	my $self = {
		_uid	=> $uid,
		_passwd	=> $passwd,
		_host	=> $host,
		_alias	=> $alias,
		_port	=> $port,
	};

	bless $self, $clazz;

	return $self;
}

sub DESTROY
{
}

# This function is for internal use -- it sends the data to the
# Collabra server, and returns what was read back.
sub _send_command($$$) {
        my ($self, $command, $method) = @_;
	#require HTTP::Headers;
	#my $req_head = new HTTP::Headers;
	#my $request = new HTTP::Request('GET', $URI, $req_head);
	my $m = $method || 'GET';
	my $request = new HTTP::Request($m, $command);
	$request->authorization_basic($self->{_uid},$self->{_passwd});
	my $response = $ua->simple_request($request);
	my $content = $response->content;
	return undef if ($response->is_error);
	return $response->content;
}

=item add_newsgroup($ngname, $prettyname, $description)

Create a new newsgroup on a Collabra news server.

=cut

sub add_newsgroup($$$$) {
        my ($self, $ngname, $prettyname, $description) = @_;

	# Log in as the user
	use MIME::Base64;
	my $auth = encode_base64($self->{_uid}.':'.$self->{_passwd});
	chomp $auth; # in case it adds a newline, as it seems to?
	my ($parent,$group) = ($ngname =~ /^(.*)\.([^.]*)$/);

	# These uri_escapes may break one day (see below)
	my $creator = uri_escape($self->{_uid});
	$group = uri_escape($group);
	$parent = uri_escape($parent);

	# Don't uri_escape, it wants "+"s, not "%20s" for spaces...
	$prettyname =~ s/\s+/\+/g;
	$description =~ s/\s+/\+/g;
	#die "'$parent', '$group', '$prettyname', '$description'\n";

	# Pass the data -- this is definitely better than the previous
	# version, but should still use an LWP::UserAgent, not IO::Socket
	use IO::Socket;
	my $socket = IO::Socket::INET->new(PeerAddr => $host,
					PeerPort => $port,
					Proto => "tcp",
					Type => SOCK_STREAM)
	or die "Couldn't connect to $host:$port : $@\n";

	my $content = "grpcreat=$creator\&group=$group\&prefngc=$parent\&action=new\&grpprname=$prettyname\&grpdesc=$description\&grptype=discussion\&localremote=remote\&flag=local\&moderator=\&gatewayaddr=\&grpalias=";
	print "I will send: $content, which is ".length($content)." long\n";

	# ... do something with the socket
	print $socket "POST /news-$alias/bin/madd HTTP/1.0\n";
	print $socket "Referer: http://$host:$port/news-$alias/bin/madd?action=new\&group=$parent\n";
	print $socket "Connection: Keep-Alive\n";
	print $socket "User-Agent: Mozilla/4.51 [en] (X11; I; Linux 2.2.11 i686)\n";
	print $socket "Host: $host:$port\n";
	print $socket "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\n";
	print $socket "Accept-Encoding: gzip\n";
	print $socket "Accept-Language: en\n";
	print $socket "Accept-Charset: iso-8859-1,*,utf-8\n";
	print $socket "Authorization: Basic $auth\n";
	print $socket "Cookie: adminReferer=http://$host:$port/news-$alias/bin/mlaunch?group=\n";
	print $socket "Content-type: application/x-www-form-urlencoded\n";
	print $socket "Content-length: ".length($content)."\n\n$content\n";

	# Read the results
	my $success = 0;
	my $error = 'Undefined error (please report this anomaly!)';
	while(<$socket>) {
		if (m#\("<br><h2>Operation completed</h2>"\)#) {
			$success = 1;
			last;
		} elsif (m#\("Incorrect Usage:([^"]+)"\)#) {
			$success = 0;
			$error = $1;
			last;
		} elsif (m#401 Unauthorized#) {
			$success = 0;
			$error = 'Proper authorization is required for this area. Either your browser does not perform authorization, or your authorization has failed.';
			last;
		}
		print 'Socket: '.$_;
	}
	shutdown($socket, 2);

	# Return the results
	if ($success) {
		return "Successfully created '$ngname'\n";
	} else {
		return "Failed to created '$ngname':\n$error\n";
	}
}

=item remove_newsgroup($ngname)

Remove an existing newsgroup on a Collabra news server.

=cut

sub remove_newsgroup($$) {
        my ($self, $ngname) = @_;

	# Log in as the user
	use MIME::Base64;
	my $auth = encode_base64($self->{_uid}.':'.$self->{_passwd});

	# Pass the data -- this is definitely better than the previous
	# version, but should still use an LWP::UserAgent, not IO::Socket
	use IO::Socket;
	my $socket = IO::Socket::INET->new(PeerAddr => $host,
					PeerPort => $port,
					Proto => "tcp",
					Type => SOCK_STREAM)
	or die "Couldn't connect to $host:$port : $@\n";

	my $content = "";

	# ... do something with the socket
#my $content = "group=$ngname&localremote=local";
#print $socket "POST /news-$alias/bin/mrem HTTP/1.0\n";
#print $socket "Referer: http://$host:$port/news-$alias/bin/mrem?nothing=0&group=junk.deleteeleven\n";
	print $socket "GET /news-$alias/bin/mrem?nothing=0&group=$ngname HTTP/1.0\n";
	print $socket "Referer: http://$host:$port/news-$alias/bin/maction?group=$ngname\n";
	print $socket "Connection: Keep-Alive\n";
	print $socket "User-Agent: Mozilla/4.51 [en] (X11; I; Linux 2.2.11 i686)\n";
	print $socket "Host: $host:$port\n";
	print $socket "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\n";
	print $socket "Accept-Encoding: gzip\n";
	print $socket "Accept-Language: en\n";
	print $socket "Accept-Charset: iso-8859-1,*,utf-8\n";
	print $socket "Authorization: Basic $auth\n";
	print $socket "Cookie: adminReferer=http://$host:$port/news-$alias/bin/mlaunch?group=\n";
	print $socket "Content-type: application/x-www-form-urlencoded\n";
	print $socket "Content-length: ".length($content)."\n\n$content\n";

	# Read the results
	my $success = 0;
	my $error = 'Undefined error (please report this anomaly!)';
	while(<$socket>) {
		if (m#\("<b>Discussion group removal complete.</b>"\)#) {
			$success = 1;
			last;
		} elsif (m#\("Incorrect Usage:([^"]+)"\)#) {
			$success = 0;
			$error = $1;
			last;
		} elsif (m#401 Unauthorized#) {
			$success = 0;
			$error = 'Proper authorization is required for this area. Either your browser does not perform authorization, or your authorization has failed.';
			last;
		}
		print 'Socket: '.$_;
	}
	shutdown($socket, 2);

	# Return the results
	if ($success) {
		return "Successfully remove '$ngname'\n";
	} else {
		return "Failed to remove '$ngname':\n$error\n";
	}
}

=item delete_all_articles($ngname)

Delete all articles in the specified newsgroup (untested as a yet).

=cut

sub delete_all_articles($$$$$)
{
	my ($self, $ng, $from, $user, $pass) = @_;

#	open(TMPFILE, ">/tmp/collabra-pm.log") || die "Can't open collabra-pm.log";

	my $nClient = new News::NNTPClient($host);
	if (!$nClient) {
#		print TMPFILE "Can't connect to $host!\n";
#		close(TMPFILE);
		return 0;
	}
	if (!$nClient->authinfo($self->{_uid}, $self->{_passwd})) {
#		print TMPFILE "Bad authinfo ($self->{_uid}, $self->{_passwd})!\n";
#		close(TMPFILE);
		return 0;
	}
	$nClient->mode_reader;

	my ($first, $last) = ($nClient->group($ng));
#	print TMPFILE "$ng: ($first, $last)\n";

	my %msgIDH = ();

	for (; $first <= $last; $first++) {
#		if ($first != $last) {
#			print TMPFILE "$first,";
#		} else { print TMPFILE "$first.\n"; }
		my @article;
		if (@article = $nClient->article($first)) {
			my @IDs = grep(/^Message-ID: /,@article);
			if ($#IDs > 1) {
				carp "Multiple IDs for ", @article;
				return 0;
			}
			$IDs[0] =~ s/Message-ID: //;
			$msgIDH{$IDs[0]}++;
		}
	}

	foreach my $m (keys %msgIDH) {
#		print TMPFILE "Issuing cancel for $m:\n";
		my @header = (
			"Newsgroups: $ng",
			"From: $from",
			"User-Agent: News::Collabra/$VERSION",
			'Organization: My organisation',
			'Distribution: myorg-only',
			'Content-Type: text/html',
			"Subject: cancel $m",
			"References: $m",
			"Control: cancel $m"
		);
#		print TMPFILE join("\n", @header), "\n\n";
		my @body = (
			'This message was cancelled by '. $self->{_uid} .'.'
		);
		$nClient->post(
			@header,
			"", # neck (blank line between header and body :-)
			@body
		);
	}

#	close(TMPFILE);

	return 1;
}

###########################################################################
# The following two functions are for internal use only.  HTML::Parser
# probably does this better...
#
# parseTag: an internal function to get name/values out of HTML
sub parseTag {
	my $tag = shift;
	# We don't know what order name/value are in:
	my ($name) = $tag =~ m#name\s*=\s*"([^"]*)"#si;
	my ($value) = $tag =~ m#value\s*=\s*"([^"]*)"#si;
	return ($name,$value);
}

# parseSelect: an internal function to get name/values out of HTML
sub parseSelect {
	my $tag = shift;
	# selected may not exist, or may be more than we want
	my ($name,$selected) = $tag =~ m#name\s*=\s*"([^"]*)".*?<\s*option selected\s*>([^<]+)#si;
	return ($name,$selected);
}

=item get_ng_acls($ngname)

Get the ACLs for the specified newsgroup.

=cut

# This hasn't been tested against non-existant ngs, etc.
sub get_ng_acls($$) {
	my ($self, $ngname) = shift;
	return undef if !defined $ngname;

	# Log in as the user
	use MIME::Base64;
	my $auth = encode_base64($self->{_uid}.':'.$self->{_passwd});
	my (%acl,%role);

	# Pass the data -- this is definitely better than the previous
	# version, but should still use an LWP::UserAgent, not IO::Socket
	use IO::Socket;
	my $socket = IO::Socket::INET->new(PeerAddr => $host,
					PeerPort => $port,
					Proto => "tcp",
					Type => SOCK_STREAM)
	or die "Couldn't connect to $host:$port : $@\n";

	my $content = "";

	# ... do something with the socket
	print $socket "GET /news-$alias/bin/maci?nothing=0&group=$ngname HTTP/1.0\n";
	print $socket "Referer: http://$host:$port/news-$alias/bin/maction?group=$ngname\n";
	print $socket "Connection: Keep-Alive\n";
	print $socket "User-Agent: Mozilla/4.51 [en] (X11; I; Linux 2.2.11 i686)\n";
	print $socket "Host: $host:$port\n";
	print $socket "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\n";
	print $socket "Accept-Encoding: gzip\n";
	print $socket "Accept-Language: en\n";
	print $socket "Accept-Charset: iso-8859-1,*,utf-8\n";
	print $socket "Authorization: Basic $auth\n";
	print $socket "Cookie: adminReferer=http://$host:$port/news-$alias/bin/mlaunch?group=$ngname\n";
	print $socket "Content-type: application/x-www-form-urlencoded\n";
	print $socket "Content-length: ".length($content)."\n\n$content\n";

	# Read the results
	my $success = 0;
	my $error = 'Undefined error (please report this anomaly!)';
	my @lines = <$socket>;
	$content = join('',@lines);
	# ACLs set from higher in the hierarchy
	while($content =~ m#(.*)(<input\s+[^>]*"(u|g)list\d+"\s*[^>]*>)(.*)#si) {
		$content = $1.$4;
		my ($name,$value) = parseTag($2);
		$acl{$name} = $value;
		$success++;
	}
	# Editable at this level
	while($content =~ m#(.*)(<input\s+[^>]*"(user|group)s\d+"\s*[^>]*>)(.*)#si) {
		$content = $1.$4;
		my ($name,$value) = parseTag($2);
		$acl{$name} = $value;
		$success++;
	}
	# Auth settings for editable at this level
	while($content =~ m#(.*)(<select\s+.*?name="role\d+".*?/select>)(.*)#si) {
		$content = $1.$3;
		my ($name,$value) = parseSelect($2);
		$role{$name} = $value;
		$success++;
	}
	shutdown($socket, 2);

	# Return the results
	if ($success) {
		print "Successfully found $success ACLs for '$ngname'\n";
		print "ACLs:\n";
		foreach my $k (keys %acl) {
			print "$k => $acl{$k}\n";
		}
		print "Auth settings:\n";
		foreach my $k (keys %role) {
			print "$k => $role{$k}\n";
		}
	} else {
		print "Failed find ACLs for '$ngname':\n$error\n";
	}
}

=item add_ng_acl($ngname,$who,$role)

Add a new ACL to the specified newsgroup.

=cut

# This hasn't been finished yet :-)
sub add_ng_acl($$$$) {
	return undef;
}

=item get_properties($ngname)

Get the display properties for the specified newsgroup.

=cut

sub get_properties($$) {
	my ($self, $ngname) = @_;
}

=item set_properties($ngname,$pretty_name,$description)

Set the display properties for the specified newsgroup.

=cut

sub set_properties($$$$) {
	my ($self, $ngname, $pretty_name, $description) = @_;

#	print $socket "POST /news-$alias/bin/madd HTTP/1.0\n";
#	print $socket "Referer: http://$host:$port/news-$alias/bin/madd?action=edit&group=myorg.test\n";
#	print $socket "Cookie: adminReferer=http://$host:$port/news-$alias/bin/mlaunch?group=myorg.test\n";
#	print $socket "grpcreat=&group=myorg.test&action=edit&grpprname=myorg.test&grpdesc=Test+group+for+myorg&grptype=discussion&flag=local&moderator=&gatewayaddr=&grpalias=\n";
}

=item _is_server_port_listening

A fundamental check for the server, used by server_status -- if we
can't run a command, is the server listening at all?  If this fails,
manual action is required to start the admin server (i.e. the command
line scripts to start the HTTP admin server -- look for a file called
'start-admin' in your server installation directory).

=cut

sub _is_server_port_listening() {
	my $self = shift;

	if (my $socket = IO::Socket::INET->new(PeerAddr => $host,
					PeerPort => $port,
					Proto => "tcp",
					Type => SOCK_STREAM)) {
		shutdown($socket, 2);
		return 1;
	}
	warn "No admin server: couldn't connect to $host:$port : $@\n";
	return 0;
}

=item server_start

Start the Collabra newsserver instance.  Returns 1 on success, 0 if
the server was already running (no other error states have been
observed).

=cut

sub server_start() {
	my $self = shift;

	my $ret = $self->_send_command('http://$host:$port/news-$alias/bin/start');
	return 0 if $ret =~ m#'Server already running'#si;
	return 1;
}

=item server_status

Returns status information about the Collabra newsserver instance (in
HTML -- grep for '<b>not</b>' if you want an off/on indicator).

=cut

sub server_status() {
	my $self = shift;

	my $ret = $self->_send_command('http://$host:$port/news-$alias/bin/pcontrol');
	if (!defined $ret) {
		# Failed -- we should warn in DEBUG mode
		# Is the admin server running?
		if (!_is_server_port_listening()) {
			# Admin server not running -- should warn in DEBUG mode
			return undef;
		}
		return $ret;
	}
	$ret =~ s#.*(<h2>[^<]+</h2>\s*<pre>)#$1#si;
	$ret =~ s#(</pre>).*#$1#si;
	return $ret;
}

=item server_stop

Start the Collabra newsserver instance.  Returns 1 on success, 0 if
the server was already stopped (no other error states have been
observed).

=cut

sub server_stop($) {
	my $self = shift;

	my $ret = $self->_send_command('http://$host:$port/news-$alias/bin/shutdown');
	return 0 if $ret =~ m#'Server already down'#si;
	return 1;
}

=back

=head2 BUGS

This module has only been tested on a newsserver with the local (ie.
supplied with Collabra) directory.  Reports on servers with full
directory servers would be appreciated!  Also, the test server only had
one newsserver instance.  Tests with multiple newsservers on the one
admin server or multiple newsservers on different servers would also be
appreciated.

=head2 AUTHOR

Nathan Bailey C<nate@cpan.org>

=head2 COPYRIGHT

Copyright 1999-2002 Nathan Bailey.  All rights reserved.  This module
is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free
Software Foundation; either version 1, or (at your option) any later
version.

=cut

1;
