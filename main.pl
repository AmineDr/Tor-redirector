use Switch;
use LWP::UserAgent;
use JSON;

my $os_name = `awk -F= '\$1=="ID_LIKE" { print \$2 ;}' /etc/os-release`;

sub get_user {
	my $username;
	if ($os_name =~ /[D,d]ebian/) {
		$username = "debian-tor";
	}

	elsif (($os_name =~ /[F,f]edora/) || ($os_name =~ /[C,c]entos/)) {
		$username = "toranon";
	}

	else {
		$username = "tor";
	}

	return $username;
}

sub get_os_name {
	my $distro;

	if ($os_name =~ /[F,f]edora/) {
		$distro = "fedora";
	}

	elsif ($os_name =~ /[A,a]rch/) {
		$distro = "arch";
	}

	elsif ($os_name =~ /[C,c]entos/) {
		$distro = "centos"
	}

	else {
		$distro = "debian";
	}

	return $distro;
}


sub usage {
	print "
		\r \t\t#Commands#
		\r +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		\r|\tCommand       Description             |
		\r|\t+-+-+-+       +-+-+-+-+-+             |
		\r|\tinstall       Install dependencies    |
		\r|\tstart         Start routing           |
		\r|\tstop          Stop routing            |
		\r|\trestart       Restart the process     |
		\r|\tcheck         check status and get IP |
		\r +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		\n";
}

sub install {
	my $OS = get_os_name();

	system ("sudo mkdir -p /etc/tor");

	if ($OS eq "debian") {
		system ("sudo apt-get install tor iptables");
		system ("sudo cp .configs/debian-torrc /etc/tor/torrc");
	}

	elsif ($OS eq "arch") {
		system ("sudo pacman -S tor iptables");
		system ("sudo cp .configs/arch-torrc /etc/tor/torrc");
	}

	elsif ($OS eq "fedora") {
		system ("sudo dnf install tor iptables");
		system ("sudo cp .configs/fedora-torrc /etc/tor/torrc");
	}

	elsif ($OS eq "centos") {
		system ("sudo yum install epel-release tor iptables");
		system ("sudo cp .configs/centos-torrc /etc/tor/torrc");
	}

	else {
		system ("sudo pacman -S tor iptables");
		system ("sudo cp .configs/arch-torrc /etc/tor/torrc");
	}

	system ("sudo chmod 644 /etc/tor/torrc");
	print "\n [+] Successfully intalled dependencies. \n"
}

sub start {
		my $dns_port = "9061";
		my $transfer_port = "9051";
		my @table = ("nat", "filter");
		my $network = "10.66.0.0/255.255.0.0";

		my $user = get_user();

		if (-e "/etc/init.d/tor") {
			system ("sudo /etc/init.d/tor start > /dev/null");
		}

		else {
			system ("sudo systemctl start tor");
		}

		foreach my $table (@table) {
			my $target = "ACCEPT";

			if ($table eq "nat") {
				$target = "RETURN";
			}

			system ("sudo iptables -t $table -A OUTPUT -m state --state ESTABLISHED -j $target");
			system ("sudo iptables -t $table -F OUTPUT");
			system ("sudo iptables -t $table -A OUTPUT -m owner --uid $user -j $target");

			my $match_dns_port = $dns_port;

			if ($table eq "nat") {
				$target = "REDIRECT --to-ports $dns_port";
				$match_dns_port = "53";
			}

			system ("sudo iptables -t $table -A OUTPUT -p udp --dport $match_dns_port -j $target");
			system ("sudo iptables -t $table -A OUTPUT -p tcp --dport $match_dns_port -j $target");

			if ($table eq "nat") {
				$target = "REDIRECT --to-ports $transfer_port";
			}

			system ("sudo iptables -t $table -A OUTPUT -d $network -p tcp -j $target");

			if ($table eq "nat") {
				$target = "RETURN";
			}

			system ("sudo iptables -t $table -A OUTPUT -d 127.0.0.1/8    -j $target");
			system ("sudo iptables -t $table -A OUTPUT -d 192.168.0.0/16 -j $target");
			system ("sudo iptables -t $table -A OUTPUT -d 172.16.0.0/12  -j $target");
			system ("sudo iptables -t $table -A OUTPUT -d 10.0.0.0/8     -j $target");

			if ($table eq "nat") {
				$target = "REDIRECT --to-ports $transfer_port";
			}

			system ("sudo iptables -t $table -A OUTPUT -p tcp -j $target");
		}

		system ("sudo iptables -t filter -A OUTPUT -p udp -j REJECT");
		system ("sudo iptables -t filter -A OUTPUT -p icmp -j REJECT");

		return true;
}

sub get_status {
	my $check_tor  = "https://check.torproject.org/api/ip";
	my $user_agent = LWP::UserAgent -> new();
	my $req   = $user_agent -> get($check_tor);
	my $req_code  = $req -> code();

	if ($req_code == "200") {
		my $data = decode_json ($req -> content);

		my $ip  = $data -> {'IP'};
		my $is_tor = $data -> {'IsTor'};

		if ($is_tor){
			print "\r[+] Tor activated.\n\r[+] IP: $ip";
		}
		else {
			print "\r[-] Tor is not activated.\n\r[+] IP: $ip\n";
		}

	}
	else {
		print "\r[*] Connection failed, Exiting...\n";
	}
}

sub stop {
	my @table = ("nat", "filter");

	foreach my $table (@table) {
		system ("sudo iptables -t $table -F OUTPUT");
		system ("sudo iptables -t $table -F OUTPUT");
	}

	if (-e "/etc/init.d/tor") {
		system ("sudo /etc/init.d/tor stop > /dev/null");
	}

	else {
		system ("sudo systemctl stop tor");
	}

	return true;
}

sub main {
	my $arg = $ARGV[0];
	switch ($arg) {
		case "stop" {
			stop();
			print "[+] Tor traffic redirecting stopped.\n";
		}

		case "start" {
			my $start_status = start();
			if ($start_status eq true){
				print "[+] Started successfully\n";
			}
			else {
				print "[-] Unhandled error while starting program.\n[+] Exiting...\n"
			}
		}

		case "check" {
			get_status();
		}

		case "restart" {
			stop();
			start();
		}

		case "install" {
			install();
		}

		usage();
	}
}

main();
exit;
