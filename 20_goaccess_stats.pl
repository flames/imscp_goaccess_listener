# i-MSCP Listener::Named::Slave::Provisioning listener file
# Copyright (C) 2015 Arthur Mayer <mayer.arthur@gmail.com>
# Listener file is based on features and functions of the i-MSCP Listener API
# Perl script is based on information from numerous comments at stackoverflow, perl and cpan
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

#
## Provides GoAccess log analyzer as alternative to AWStats.
## This listener file requires i-MSCP 1.4.2 or newer.
## GoAccess will be available at
##   - http://customer-domain.tld/goaccess
##   - https://customer-domain.tld/goaccess (if you use ssl)
#

package Listener::Goaccess::Stats;

use strict;
use warnings;
use iMSCP::Debug;
use iMSCP::Dir;
use iMSCP::EventManager;
use iMSCP::File;
use iMSCP::TemplateParser;
use iMSCP::Execute;

#
## Event listeners
#

my $eventManager = iMSCP::EventManager->getInstance();

$eventManager->register('afterFrontEndInstall', sub {
        # Example, how to execute commands in lister (took from some dovecot listener)
        #execute( "dovecot --version", \ my $stdout, \ my $stderr );
        #if (version->parse( "$stdout" ) < version->parse( '2.1.0' )) {
        #    warning( "The 60_dovecot_service_login.pl Listener file requires Dovecot version 2.1.x or newer. Your version is: $stdout" );
        #    return 0;
        #}

        # Install needed packages and prerequisites for spanminus
        #CGI                  apt-get install libcgi-pm-perl
        #HTTP::Daemon         apt-get install libhttp-daemon-perl
        my $rs = execute(
            [
                'apt-get', '--assume-yes', '--no-install-recommends', '--quiet', 'install', 'cpanminus', 'cpanoutdated',
                'libcgi-pm-perl', 'libhttp-daemon-perl', 'libfile-pid-perl'
            ],
            \my $stdout,
            \my $stderr
        );
        debug( $stdout ) if $stdout;
        error( $stderr || 'Unknown error' ) if $rs;


        # Install needed CPAN Perl modules through cpanminus
        $rs = execute(
            [
                'cpanm', '--notest', '--quiet',
                'HTTP::Status', 'HTTP::Message', 'Authen::Htpasswd', 'File::Pid'
            ],
            \$stdout,
            \$stderr
        );
        debug($stdout) if $stdout;
        error($stderr || 'failed') if $rs;


        # Create GoAccess HTTP wrapper daemon
        my $fileContent = <<'EOF';
#!/usr/bin/perl
# GoAccess log analyzer HTTP wrapper daemon
use HTTP::Daemon;
use HTTP::Status;
use HTTP::Response;
use CGI;
use POSIX;
use File::Pid;
use Authen::Htpasswd;

my $ListenAddress = '0.0.0.0'; # Listening IP address
my $ListenPort = 8890; # Listening TCP port
my $totalChildren = 10; # Number of listening children to keep alive
my $childLifetime = 10; # Let each child serve up to this many requests
my $logFile = "/var/log/goaccess_stats.log";
my %children;
my $children = 1;
my $pidFile = "/var/run/goaccess_stats.pid";
my $pwFile = '/etc/apache2/.imscp_awstats';

&_daemonize;

my $d = HTTP::Daemon->new( LocalPort => $ListenPort, LocalAddr => $ListenAddress, Reuse => 1, Timeout => 180 ) or die "Cannot create socket: $!\n";

my $pwfile = Authen::Htpasswd->new($pwFile, { encrypt_hash => 'md5' });

warn ("master is ", $d->url);

&_spawn_children;
&_keep_ticking;
exit;

sub _spawn_children {
    for (1..$totalChildren) {
        _new_child();
    }
}

sub _keep_ticking {
    while ( 1 ) {
        sleep;
        for (my $i = $children; $i < $totalChildren; $i++ ) {
          _new_child();
        }
    };
}

sub _new_child {
    my $pid;
    my $sigset = POSIX::SigSet->new(SIGINT);
    sigprocmask(SIG_BLOCK, $sigset) or die "Can't block SIGINT for fork: $!";
    die "Cannot fork child: $!\n" unless defined ($pid = fork);
    if ($pid) {
        $children{$pid} = 1;
        $children++;
        warn "forked new child, we now have $children children";
        return;
    }

    my $i;
    while ($i < $childLifetime) {
        $i++;
        my $c = $d->accept or last;
        $c->autoflush(1);
        _log_message ("connect:". $c->peerhost . "\n");
        my $r = $c->get_request(1) or last;
        if ($r->method ne 'GET') {
            $error = $c->peerhost . " " . $r->uri->path . " made weird request.\n";
            _log_message ($error);
            _http_error($c, RC_FORBIDDEN, $error);
        }
        _log_message ($c->peerhost . " " . $r->uri->path . "\n");

        if ($r->uri->path eq '/') {
            $error = $c->peerhost . " " . $r->uri->path . " Missing parameter.\n";
            _log_message ($error);
            _http_error($c, RC_FORBIDDEN, $error);
        } elsif ($r->uri->path =~ m/^\/(.+)/) {
            my $accesslog_path = '/var/www/virtual/*/logs/' . substr($r->uri->path, 1) . '/access.log';
            my @accesslog_file = glob $accesslog_path;
            if (@accesslog_file != 1) {
                $error = $c->peerhost . " " . $r->uri->path . " Wrong parameter.\n";
                _log_message ($error);
                _http_error($c, RC_FORBIDDEN, $error);
            } else {
                my @splitpath = split m%/%, $accesslog_file[0];
                my $userdomain = $splitpath[4];
                my $statsdomain = substr($r->uri->path, 1);
                my ($user, $pass) = $r->authorization_basic;
                if (defined($user) && $user eq $userdomain && $pwfile->check_user_password($user, $pass)) {
                    my $accesslog_parse = '/usr/bin/goaccess '.$accesslog_file[0].' -a 2>&1';
                    my $content = qx($accesslog_parse);
                    _http_response(
                        $c,
                        {content_type => 'text/html'},
                        $content,
                    );
                    _log_message ("Logged in.\n");
                } else {
                    $c->send_basic_header(401);
                    $c->print('WWW-Authenticate: Basic Realm="GoAccess"');
                    $error = $c->peerhost . " " . $r->uri->path . " Auth error.\n";
                    _log_message ($error);
                    _http_error($c, RC_FORBIDDEN, $error);
                }
            }
        } else {
            _log_message ($c->peerhost . " " . $r->uri->path . " Page not found.\n");
            _http_error($c, RC_NOT_FOUND);
        }
        _log_message ("disconnect:" . $c->peerhost . " - ct[$i]\n");
        $c->close;
    }
    warn "child terminated after $i requests";
    exit;
}

sub _REAPER {
    my $stiff;
    while (($stiff = waitpid(-1, &WNOHANG)) > 0) {
        warn ("child $stiff terminated -- status $?");
        $children--;
        $children{$stiff};
    }
    $SIG{CHLD} = \&_REAPER;
}

sub _daemonize {
    my $pid = fork;
    defined ($pid) or die "Cannot start daemon: $!";
    print "Parent daemon running.\n" if $pid;
    exit if $pid;
    POSIX::setsid();
    close (STDOUT);
    close (STDIN);
    close (STDERR);
    my $pidfile = File::Pid->new( { file => $pidFile, } );
    $pidfile->write or die "Can't write PID file, /dev/null: $!";
    $SIG{__WARN__} = sub {
            &_log_message ("NOTE! " . join(" ", @_));
    };
    $SIG{__DIE__} = sub {
        &_log_message ("FATAL! " . join(" ", @_));
        exit;
    };
    $SIG{HUP} = $SIG{INT} = $SIG{TERM} = sub {
      my $sig = shift;
      $SIG{$sig} = 'IGNORE';
      kill 'INT' => keys %children;
      $pidfile->remove if defined $pidfile;
      die "killed by $sig\n";
      exit;
    };
    $SIG{CHLD} = \&_REAPER;
}

sub _log_message {
    my $message = shift;
    (my $sec, my $min, my $hour, my $mday, my $mon, my $year) = gmtime();
    $mon++;
    $mon = sprintf("%0.2d", $mon);
    $mday = sprintf("%0.2d", $mday);
    $hour = sprintf("%0.2d", $hour);
    $min = sprintf("%0.2d", $min);
    $sec = sprintf("%0.2d", $sec);
    $year += 1900;
    my $time = qq{$year/$mon/$mday $hour:$min:$sec};
    open (FH, ">>" . $logFile);
    print FH $time . " - " . $message;
    close (FH);
}

sub _http_error {
    my ($c, $code, $msg) = @_;
    $c->send_error($code, $msg);
}

sub _http_response {
    my $c = shift;
    my $options = shift;
    $c->send_response(
        HTTP::Response->new(
            RC_OK,
            undef,
            [
                'Content-Type' => $options->{content_type},
                'Cache-Control' => 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
                'Pragma' => 'no-cache',
                'Expires' => 'Thu, 01 Dec 1994 16:00:00 GMT',
            ],
            join("\n", @_),
        )
    );
}
EOF
        my $file = iMSCP::File->new(
            filename => "/usr/local/sbin/goaccess_stats.pl"
        );
        $rs = $file->set($fileContent);
        $rs ||= $file->save();
        $rs ||= $file->owner("root", "root");
        $rs ||= $file->mode(0755);


        # Create systemd unit file for the daemon
        $fileContent = <<'EOF';
[Unit]
Description=GoAccess log analyzer HTTP wrapper daemon
After=network.target

[Service]
Type=forking
PIDFile=/var/run/goaccess_stats.pid
ExecStart=/usr/local/sbin/goaccess_stats.pl

[Install]
WantedBy=multi-user.target
EOF
        $file = iMSCP::File->new(
            filename => "/etc/systemd/system/goaccess_stats.service"
        );
        $rs = $file->set($fileContent);
        $rs ||= $file->save();
        $rs ||= $file->owner("root", "root");
        $rs ||= $file->mode(0644);


        # Enable the systemd unit
        $rs = execute(
            ['systemctl enable goaccess_stats.service'],
            \$stdout,
            \$stderr
        );
        debug( $stdout ) if $stdout;
        error( $stderr || 'Enable Systemd unit failed' ) if $rs;


        # Start the GoAccess HTTP wrapper daemon (restart, if already running)
        $rs = execute(
            ['systemctl stop goaccess_stats.service; systemctl start goaccess_stats.service'],
            \$stdout,
            \$stderr
        );
        debug( $stdout ) if $stdout;
        error( $stderr || 'Start daemon failed' ) if $rs;


        # TODO: sysvinit script will be added later
        # Create and enable the sysvinit script
        #/etc/init.d/goaccess_stats
        #update-rc.d goaccess_stats defaults
    }
);

# Add a proxy to customer domains
$eventManager->register('beforeHttpdBuildConf', sub {
        my ($cfgTpl, $tplName, $data) = @_;

        return 0 unless $tplName eq 'domain.tpl'
            && grep( $_ eq $data->{'VHOST_TYPE'}, ( 'domain', 'domain_ssl' ) );

        my $cfgProxy = <<'EOF';
    <Location /goaccess>
        ProxyPass http://127.0.0.1:8890/{DOMAIN_NAME} retry=1 acquire=3000 timeout=600 Keepalive=On
        ProxyPassReverse http://127.0.0.1:8890/{DOMAIN_NAME}
    </Location>
EOF

        ${$cfgTpl} = replaceBloc(
            "# SECTION addons BEGIN.\n",
            "# SECTION addons END.\n",
            "    # SECTION addons BEGIN.\n".
                getBloc(
                    "# SECTION addons BEGIN.\n",
                    "# SECTION addons END.\n",
                    ${$cfgTpl}
                ).process({DOMAIN_NAME => $data->{'DOMAIN_NAME'}}, $cfgProxy)
                ."    # SECTION addons END.\n",
            ${$cfgTpl}
        );
        0;
    }
);

1;
__END__
