#! /usr/bin/perl
#
# $Id$
# Copyright (C) 2004-2007 Jan Kratochvil <project-tcpoverudp@jankratochvil.net>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; exactly version 2 of June 1991 is required
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


use strict;
use warnings;
use Getopt::Long 2.35;	# >=2.35 for: {,}
require IO::Socket::INET;
use Fcntl;
use Carp qw(cluck confess);
use Socket;
use Time::HiRes qw(time);


my $READ_SIZE=256;	# 96kbit = 47 x 256B
my $MAX_UNACKED=8;

my $V=1;
$|=1;
for (qw(PIPE)) {
	$SIG{$_}=eval "sub { cluck 'INFO: Got signal SIG$_'; };";
}

my $D;
my $opt_udp_listen_port;
my $opt_udp_server_addr;
my $opt_udp_server_port;
my @opt_tcp_listen_port;
my @opt_tcp_forward_addr;
my @opt_tcp_forward_port;
my $opt_timeout=0.1;
my $opt_recvloss=0;
die if !GetOptions(
		  "udp-listen-port=s",\$opt_udp_listen_port,
		  "udp-server-addr=s",\$opt_udp_server_addr,
		  "udp-server-port=s",\$opt_udp_server_port,
		  "tcp-listen-port=s{,}",\@opt_tcp_listen_port,
		  "tcp-forward-addr=s{,}",\@opt_tcp_forward_addr,
		  "tcp-forward-port=s{,}",\@opt_tcp_forward_port,
		"t|timeout=s",\$opt_timeout,
		  "recvloss=s",\$opt_recvloss,
		"d|debug+",\$D,
		);

die "udp-server- addr/port inconsistency" if !$opt_udp_server_addr != !$opt_udp_server_port;
die "udp- listen/sever port inconsistency" if !$opt_udp_listen_port == !$opt_udp_server_port;
die "tcp-forward- addr/port inconsistency" if !@opt_tcp_forward_addr != !@opt_tcp_forward_port;
die "tcp- listen/forward port inconsistency" if !@opt_tcp_listen_port == !@opt_tcp_forward_port;
die "udp vs. tcp inconsistency" if !$opt_udp_listen_port == !@opt_tcp_listen_port;

my @sock_tcp;
for my $tcp_listen_port (@opt_tcp_listen_port) {
	my $sock_tcp=IO::Socket::INET->new(
		LocalPort=>$tcp_listen_port,
		Proto=>"tcp",
		Listen=>5,
		ReuseAddr=>1,
	) or die "socket(): $!";
	push @sock_tcp,$sock_tcp;
}

my $sock_udp;
if ($opt_udp_listen_port) {
	$sock_udp=IO::Socket::INET->new(
		Proto=>"udp",
		LocalPort=>$opt_udp_listen_port,
	) or die "socket(): $!";
} else {
	$sock_udp=IO::Socket::INET->new(
		Proto=>"udp",
		PeerAddr=>$opt_udp_server_addr,
		PeerPort=>$opt_udp_server_port,
	) or die "socket(): $!";
}

sub id_new()
{
	our $id;
	$id||=0;
	return $id++;
}

my %stats;
sub stats($)
{
	my($name)=@_;

	$stats{$name}++;
	our $last;
	$last||=time();
	my $now=time();
	return if $now<$last+1 && !$D;
	$last=$now;
	print join(" ","stats:",map(("$_=".$stats{$_}),sort keys(%stats))).($D ? "\r" : "\r");
}

my $peer_addr;
my $MAGIC=0x56319EA6;

sub sendpkt($;$)
{
	my($data,$stats)=@_;

	if (!$peer_addr) {
		cluck "Still no peer to send";
		stats("sentearly");
		return;
	}
	$data=pack "Na*",$MAGIC,$data;
	if (!send $sock_udp,$data,0,$peer_addr) {
		cluck "Error sending packet: $!";
		$stats="senterr";
	}
	stats($stats||"sentok");
}

sub printable($)
{
	local $_=$_[0];
	s/\W/./gs;
	return $_;
}

sub seq_new($)
{
	my($data)=@_;

	return {
		"data"=>$data,
		"timeout"=>time()+$opt_timeout,
		};
}

my %sock;
my %active;

sub sock_new($$$)
{
	my($id,$which,$stream)=@_;

	confess if $sock{$id};
	$active{$id}=$sock{$id}={
		"id"=>$id,
		"stream"=>$stream,
		"which"=>$which,	# for OPEN retransmits
		"sent_to_udp"=>0,
		"sent_queue"=>{
				0=>seq_new(undef()),
			},
		"acked_to_udp"=>0,
		"incoming"=>{
				# 5=>$udp_data,
			},
	};
}

my $TYPE_OPEN=0;	# new_id,which
my $TYPE_SEND=1;	# id,seq,data
my $TYPE_ACK=2;		# id,seq
my $TYPE_CLOSE=3;	# id,seq


$V and print localtime()." START\n";
if ($opt_udp_server_port) {
	my $host=gethostbyname($opt_udp_server_addr) or die "resolving $opt_udp_server_addr: $!";
	$peer_addr=sockaddr_in($opt_udp_server_port,$host) or die "assembling $opt_udp_server_addr:$opt_udp_server_port";
	my($back_port,$back_host)=sockaddr_in $peer_addr;
	$back_host=inet_ntoa $back_host;
	warn "Peer server: $back_host:$back_port";
}
my $earliest;
for (;;) {
	my $rfds="";
	for my $sock_tcp (@sock_tcp) {
		vec($rfds,fileno($sock_tcp),1)=1;
	}
	vec($rfds,fileno($sock_udp),1)=1;
	for my $hashref (values(%active)) {
		next if !$hashref->{"stream"};
		next if keys(%{$hashref->{"sent_queue"}})>=$MAX_UNACKED;
		vec($rfds,fileno($hashref->{"stream"}),1)=1;
	}
	###warn "select(2)..." if $D;
	my $periodic_remaining;
	my $now=time();
	$periodic_remaining=($earliest>$now ? $earliest-$now : 0) if $earliest;
	my $got=select $rfds,undef(),undef(),$periodic_remaining;
	###warn "got from select." if $D;
	die "Invalid select(2): ".Dumper($got) if !defined $got || $got<0;

	for my $which (0..$#sock_tcp) {
		my $sock_tcp=$sock_tcp[$which];
		next if !vec($rfds,fileno($sock_tcp),1);
		my $sock_tcp_new;
		accept $sock_tcp_new,$sock_tcp or confess "Error accepting new TCP socket: $!";
		my $id=id_new();
		warn "Accepted new TCP (id=$id)" if $D;
		my $old=select $sock_tcp_new;
		$|=1;
		select $old;
		sock_new $id,$which,$sock_tcp_new;
		sendpkt pack("CNN",$TYPE_OPEN,$id,$which);
		warn "Sent OPEN (id=$id)" if $D;
	}
	for my $hashref (values(%active)) {
		next if !$hashref->{"stream"};
		my $id=$hashref->{"id"};
		next if !vec($rfds,fileno($hashref->{"stream"}),1);
		my $buf;
		fcntl($hashref->{"stream"},F_SETFL,O_NONBLOCK) or die "fnctl(,F_SETFL,O_NONBLOCK)";
		my $got=sysread $hashref->{"stream"},$buf,$READ_SIZE;
		fcntl($hashref->{"stream"},F_SETFL,0)          or die "fnctl(,F_SETFL,0)";
		#defined($got) or confess "Error reading TCP socket: $!";
		if (!$got) {
			warn "Got TCP EOF/error (id=$id)" if $D;
			my $seq=++$hashref->{"sent_to_udp"};
			$hashref->{"sent_queue"}{$seq}=seq_new(undef());
			sendpkt pack("CNN",$TYPE_CLOSE,$id,$seq);
			close $hashref->{"stream"} or confess "Error closing local socket: $!";
			delete $hashref->{"stream"};
			warn "Sent CLOSE (id=$id,seq=$seq)" if $D;
		} elsif ($got==length $buf) {
			warn "Got TCP data (id=$id,got=$got)" if $D;
			my $seq=++$hashref->{"sent_to_udp"};
			$hashref->{"sent_queue"}{$seq}=seq_new($buf);
			sendpkt pack("CNNa*",$TYPE_SEND,$id,$seq,$buf);
			warn "Sent SEND (id=$id,seq=$seq,data=".printable($buf).")" if $D;
		} else {
			confess "Invalid socket read return value: $got";
		}
	}
	if (vec($rfds,fileno($sock_udp),1)) {{
		my $udp_data;
		my $got_addr=recv $sock_udp,$udp_data,0x10000,0;
		if (!$got_addr) {
			cluck "Error receiving UDP data: $!";
			stats("recverr");
			last;
		}
		$peer_addr||=$got_addr;
		if ($got_addr ne $peer_addr) {
			my($port,$host)=sockaddr_in $got_addr;
			$host=inet_ntoa $host;
			cluck "Ignoring packet as from unidentified address: $host:$port";
			stats("ufoaddr");
			last;
		}
		my $try_retry;
		retry:
		if ($try_retry) {
			$udp_data=$try_retry;
			$try_retry=undef();
		}
		my $udp_data_orig=$udp_data;
		my($magic,$type,$id);
		($magic,$type,$id,$udp_data)=unpack "NCNa*",$udp_data;
		if (!$magic || $magic!=$MAGIC) {
			stats("badcrc");
		} elsif (rand() < $opt_recvloss) {
			warn "Got type=$type (id=$id) but it got lost" if $D;
		} elsif ($type==$TYPE_OPEN) {
			my($which);
			($which,$udp_data)=unpack "Na*",$udp_data;
			warn "Got OPEN (id=$id,which=$which)" if $D;
			die if $udp_data;
			if (!$sock{$id}) {
				my $sock_tcp_new=IO::Socket::INET->new(
					PeerAddr=>$opt_tcp_forward_addr[$which],
					PeerPort=>$opt_tcp_forward_port[$which],
					Proto=>"tcp",
				);
				if (!$sock_tcp_new) {
					sendpkt pack("CNN",$TYPE_CLOSE,$id,1);
					warn "Refused back OPEN by CLOSE (id=$id,seq=1)" if $D;
				} else {
					my $old=select $sock_tcp_new;
					$|=1;
					select $old;
					sock_new $id,$which,$sock_tcp_new;
					stats("openok");
				}
			}
			sendpkt pack("CNN",$TYPE_ACK,$id,0);
		} elsif ($type==$TYPE_SEND) {
			my($seq);
			($seq,$udp_data)=unpack "Na*",$udp_data;
			my $hashref=$sock{$id};
			if (!$hashref) {
				cluck "Got SEND but for nonexisting sock $id";
				stats("ufosock");
			} else {
				warn "Got SEND(id=$id,seq=$seq (acked_to_udp=".$hashref->{"acked_to_udp"}."),data=".printable($udp_data).")" if $D;
				if ($hashref->{"acked_to_udp"}+1>$seq) {
					stats("recvdup");
				}
				if ($hashref->{"acked_to_udp"}+1==$seq) {
					if ($hashref->{"stream"}) {
						if (length($udp_data)==((syswrite $hashref->{"stream"},$udp_data,length($udp_data)) || 0)) {
							warn "Wrote TCP data (id=$id,acked_to_udp=seq=$seq,data=".printable($udp_data).")" if $D;
						} else {
							my $seqclose=++$hashref->{"sent_to_udp"};
							$hashref->{"sent_queue"}{$seqclose}=seq_new(undef());
							warn "Refusing back OPEN by CLOSE (id=$id,seqclose=$seqclose)" if $D;
							sendpkt pack("CNN",$TYPE_CLOSE,$id,$seqclose);
						}
					}
					$hashref->{"acked_to_udp"}=$seq;
					stats("recvok");
					warn "In     order - got SEND (id=$id,seq=$seq (acked_to_udp=".$hashref->{"acked_to_udp"}.")" if $D && $D>=2;
					if (($try_retry=$hashref->{"incoming"}{$seq+1})) {
						delete $hashref->{"incoming"}{$seq+1};
						warn "Reinserted, retrying" if $D && $D>=2;
					}
				}
				if ($hashref->{"acked_to_udp"}+1<$seq) {
					warn "Out of order - got SEND (id=$id,seq=$seq (acked_to_udp=".$hashref->{"acked_to_udp"}.")" if $D && $D>=2;
					$hashref->{"incoming"}{$seq}=$udp_data_orig;
				}
			}
			if (!$hashref || $hashref->{"acked_to_udp"}+1>=$seq) {
				sendpkt pack("CNN",$TYPE_ACK,$id,$seq);
				warn "Sent ACK (id=$id,seq=$seq)" if $D;
			}
			goto retry if $try_retry;
		} elsif ($type==$TYPE_ACK) {{
			my $hashref=$sock{$id};
			if (!$hashref) {
				cluck "Got ACK but for nonexisting sock $id";
				stats("ufosock");
				last;
			}
			my($seq);
			($seq,$udp_data)=unpack "Na*",$udp_data;
			warn "Got ACK (id=$id,seq=$seq)" if $D;
			die if $udp_data;
			###exists $hashref->{"sent_queue"}{$seq} or confess "Nonexisting queue of $id: $seq";
			if (exists $hashref->{"sent_queue"}{$seq}) {
				my $data=$hashref->{"sent_queue"}{$seq}{"data"};
				die if !$seq && defined $data;
				die if $seq && defined $data && $data eq "";
				delete $hashref->{"sent_queue"}{$seq};
				if ($seq && !defined $data) {
					delete $active{$id};
					warn "Deleted active id $id (processed ACK on close)" if $D;
				}
				warn "Processed ACK (id=$id,seq=$seq); remaining:".scalar(keys(%{$hashref->{"sent_queue"}})) if $D;
			}
		}} elsif ($type==$TYPE_CLOSE) {
			my($seq);
			($seq,$udp_data)=unpack "Na*",$udp_data;
			my $hashref=$sock{$id};
			if (!$hashref) {
				cluck "Got CLOSE but for nonexisting sock $id";
				stats("ufosock");
			} else {
				warn "Got CLOSE (id=$id,seq=$seq)" if $D;
				die if $udp_data;
				if ($hashref->{"acked_to_udp"}+1>$seq) {
					stats("recvdup");
				}
				if ($hashref->{"acked_to_udp"}+1==$seq && $hashref->{"stream"}) {
					close $hashref->{"stream"} or confess "Cannot close socket of $id";
					delete $hashref->{"stream"};
					$hashref->{"acked_to_udp"}=$seq;
					confess if !$active{$id};
					delete $active{$id};
					warn "Closed the local stream, deleted it from active (id=$id,seq=$seq)" if $D;
				}
			}
			if (!$hashref || $hashref->{"acked_to_udp"}+1>=$seq) {
				sendpkt pack("CNN",$TYPE_ACK,$id,$seq);
				warn "Sent ACK of close (id=$id,seq=$seq)" if $D;
			}
		} else {
			confess "Invalid packet type $type";
		}
	}}
	$earliest=undef();
	for my $hashref (values(%active)) {
		my $id=$hashref->{"id"};
		for my $seq (sort {$a <=> $b} keys(%{$hashref->{"sent_queue"}})) {
			my $seqhashref=$hashref->{"sent_queue"}{$seq};
			my $data=$seqhashref->{"data"};
			my $when=$seqhashref->{"timeout"};
			if (time()>=$when) {
				if ($seq==0) {
					die if defined $data;
					warn "Resent OPEN (id=$id)" if $D;
					sendpkt pack("CNN",$TYPE_OPEN,$id,$hashref->{"which"}),"sentdup";
				} elsif (defined $data) {
					die if $data eq "";
					warn "Resent SEND (id=$id,seq=$seq)" if $D;
					sendpkt pack("CNNa*",$TYPE_SEND,$id,$seq,$data),"sentdup";
				} else {	# pending CLOSE
					warn "Resent CLOSE (id=$id,seq=$seq)" if $D;
					sendpkt pack("CNN",$TYPE_CLOSE,$id,$seq),"sentdup";
				}
				$when=$seqhashref->{"timeout"}=time()+$opt_timeout;
			}
			$earliest=$when if !$earliest || $when<$earliest;
			last if time()<$seqhashref->{"timeout"};
		}
	}
}