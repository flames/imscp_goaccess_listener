#!/usr/bin/perl
# Based on:
# Basic pre-forking HTTP daemon - version 2
# By Peter Cooper - http://www.petercooper.co.uk
# Inspiration and various rehashed snippetsof code from the Perl
# cfdaemon engine - http://perl-cfd.sourceforge.net
# stackoverflow, cpan and perl forum comments, documentations
#
use HTTP::Daemon;
use HTTP::Status;
use HTTP::Response;
use CGI;
use POSIX;
use File::Pid;
use Authen::Htpasswd;

my $ListenAddress = '0.0.0.0'; # Listening IP address
my $ListenPort = 8890; # Listening port
my $totalChildren = 10; # Number of listening children to keep alive
my $childLifetime = 10; # Let each child serve up to this many requests
my $logFile = "/var/log/goaccess_wrapper.log"; # Log requests and errors to this file
my %children; # Store pids of children
my $children = 1; # Store number of currently active children
my $pidFile = "/var/run/goaccess_wrapper.pid";
my $pwFile = '/etc/apache2/.imscp_awstats';

&daemonize; # Daemonize the parent

my $d = HTTP::Daemon->new( LocalPort => $ListenPort, LocalAddr => $ListenAddress, Reuse => 1, Timeout => 180 ) or die "Cannot create socket: $!\n";

my $pwfile = Authen::Htpasswd->new($pwFile, { encrypt_hash => 'md5' });

warn ("master is ", $d->url);

&_spawn_children;
&_keep_ticking;
exit;

# _spawn_children - initial process to spawn the right number of children
sub _spawn_children {
    for (1..$totalChildren) {
        _new_child();
    }
}

# _keep_ticking - a never ending loop for the parent process which just monitors
# dying children and generates new ones
sub _keep_ticking {
    while ( 1 ) {
        sleep;
        for (my $i = $children; $i < $totalChildren; $i++ ) {
          _new_child();
        }
    };
}

# _new_child - a forked child process that actually does some work
sub _new_child {
    my $pid;
    my $sigset = POSIX::SigSet->new(SIGINT); # Delay any interruptions!
    sigprocmask(SIG_BLOCK, $sigset) or die "Can't block SIGINT for fork: $!";
    die "Cannot fork child: $!\n" unless defined ($pid = fork);
    if ($pid) {
        $children{$pid} = 1; # Report a child is using this pid
        $children++; # Increase the child count
        warn "forked new child, we now have $children children";
        return; # Head back to wait around
    }

    my $i;
    while ($i < $childLifetime) { # Loop for $childLifetime requests
    #while (1) {
        $i++;
        my $c = $d->accept or last; # Accept a request, or if timed out.. die early
        $c->autoflush(1);
        _log_message ("connect:". $c->peerhost . "\n"); # We've accepted a connection!
        my $r = $c->get_request(1) or last; # Get the request. If it fails, die early
        # Insert your own logic code here. The request is in $r

        # What we do here is check if the method is not GET, if so.. send back a 403.
        #if ($r->method ne 'GET') {
        #    $error = $c->peerhost . " " . $r->uri->path . " made weird request.\n";
        #    _log_message ($error);
        #    _http_error($c, RC_FORBIDDEN, $error);
        #    #die $error;
        #}

        #_log_message ($c->peerhost . " " . $r->uri->path . "\n");

        if ($r->uri->path eq '/') {
            $error = $c->peerhost . " " . $r->uri->path . " Missing parameter.\n";
            _log_message ($error);
            _http_error($c, RC_FORBIDDEN, $error);
            #die $error;
        } elsif ($r->uri->path =~ m/^\/(.+)/) {
            my $accesslog_path = '/var/www/virtual/*/logs/' . substr($r->uri->path, 1) . '/access.log';
            my @accesslog_file = glob $accesslog_path;
            if (@accesslog_file != 1) {
                $error = $c->peerhost . " " . $r->uri->path . " Wrong parameter.\n";
                _log_message ($error);
                _http_error($c, RC_FORBIDDEN, $error);
                #die $error;
            } else {
                my @splitpath = split m%/%, $accesslog_file[0];
                my $userdomain = $splitpath[4];
                my $statsdomain = substr($r->uri->path, 1);
                #htpasswd functions:
                #my @users = $pwfile->all_users; #all users
                #my $user = $pwfile->lookup_user($username); #lookup user
                #$pwfile->check_user_password($username,$password); #check user password
                #HTTP Basic Auth works in two steps:
                #First step:
                #    Browser sends a request
                #    Server replies with a full HTTP Response (header, body) with HTTP status code 401
                #    Browser shows a (browser-specific) dialog to ask for username and password
                #    "OK" on that dialog typicalls starts step 2
                #    "Cancel" on that dialog typically shows the response body received earlier - but that depends on the browser implementation. Don't rely on it!
                #Second step:
                #    Browser re-sends the original request again, but adds an Authorization header
                #    Server checks username and password and sends a full response (header, body) with either HTTP status code 200 (OK) or 401 (in this case: "username or password wrong, try again")
                #    For code 401: See browser behavior for step 1
                #    For code 200: Show the website as usual
                #    Any other code is also valid: A 302 to redirect the user, a 500 to show an error, etc.
##############################
                my ($user, $pass) = $r->authorization_basic;
                if (defined($user) && $user eq $userdomain && $pwfile->check_user_password($user, $pass)) {
                    my $accesslog_parse = '/usr/bin/goaccess '.$accesslog_file[0].' -a 2>&1';
                    my $content = qx($accesslog_parse);
                    _http_response(
                        $c,
                        {content_type => 'text/html'},
                        #$content,
                        "yes",
                    );
                    _log_message ("YES\n");
                    #die $error;
                } else {
                    $c->send_basic_header(401);
                    $c->print('WWW-Authenticate: Basic Realm="GoAccess"');
                    # On cancel send original response
                    $error = $c->peerhost . " " . $r->uri->path . " Auth error.\n";
                    _log_message ($error);
                    _http_error($c, RC_FORBIDDEN, $error);
                    #die $error;
                }
##############################
            }
        } else {
            _log_message ($c->peerhost . " " . $r->uri->path . " Page not found.\n");
            _http_error($c, RC_NOT_FOUND);
            #die $error;
        }
        _log_message ("disconnect:" . $c->peerhost . " - ct[$i]\n"); # Log the end of the request
        $c->close;
    }
    warn "child terminated after $i requests";
    exit;
}

# REAPER - a reaper of dead children/zombies with exit codes to spare
sub REAPER {
    my $stiff;
    while (($stiff = waitpid(-1, &WNOHANG)) > 0) {
        warn ("child $stiff terminated -- status $?");
        $children--;
        $children{$stiff};
    }
    $SIG{CHLD} = \&REAPER;
}

# daemonize - daemonize the parent/control app
sub daemonize {
    my $pid = fork; # Fork off the main process
    defined ($pid) or die "Cannot start daemon: $!"; # If no PID is defined, the daemon failed to start
    print "Parent daemon running.\n" if $pid; # If we have a PID, the parent daemonized okay
    exit if $pid; # Return control to the user
    # Now we're a daemonized parent process!
    POSIX::setsid(); # Become a session leader
    close (STDOUT); # Close file handles to detach from any terminals
    close (STDIN);
    close (STDERR);
    # Create PID file of the new fork
    my $pidfile = File::Pid->new( { file => $pidFile, } );
    $pidfile->write or die "Can't write PID file, /dev/null: $!";
    # Set up signals we want to catch. Let's log warnings, fatal errors, and catch hangups and dying children
    $SIG{__WARN__} = sub {
            &_log_message ("NOTE! " . join(" ", @_));
    };
    $SIG{__DIE__} = sub {
        &_log_message ("FATAL! " . join(" ", @_));
        exit;
    };
    $SIG{HUP} = $SIG{INT} = $SIG{TERM} = sub { # Any sort of death trigger results in instant death of all
      my $sig = shift;
      $SIG{$sig} = 'IGNORE';
      kill 'INT' => keys %children;
      $pidfile->remove if defined $pidfile; # Destroy PID file on death of this child
      die "killed by $sig\n";
      exit;
    };
    $SIG{CHLD} = \&REAPER;
}

# _log_message - append messages to a log file. messy, but it works for now.
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
