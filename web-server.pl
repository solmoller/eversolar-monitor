{
    package SolarWebServer;

    use HTTP::Server::Simple::CGI;
    use base qw(HTTP::Server::Simple::CGI);
    use JSON;

    my %dispatch = (
        '/' => \&index,
        '/inverter-data' => \&inverter_data,
        '/log' => \&log,
        # ...
    );

    sub handle_request {
        my $self = shift;
        my $cgi  = shift;

        my $path = $cgi->path_info();
        my $handler = $dispatch{$path};

        if (ref($handler) eq "CODE") {
            print "HTTP/1.0 200 OK\r\n";
            $handler->($cgi);
        } else {
            print "HTTP/1.0 404 Not found\r\n";
            print $cgi->header,
                $cgi->start_html('Not found'),
                $cgi->h1('Not found'),
                $cgi->end_html;
        }
    }

    sub index {
        my $cgi  = shift;   # CGI.pm object
        return if !ref $cgi;

        open my $fh, "<www/index.html";
        my $data = do { local $/; <$fh> };

        print $cgi->header,
            $data;
    }

    sub inverter_data {
        my $cgi  = shift;   # CGI.pm object
        return if !ref $cgi;

        print $cgi->header('application/json');

        open FILE, "</tmp/eversolar";
        while(<FILE>) {
             print $_;
        }
    }

    sub log {
        my $cgi  = shift;   # CGI.pm object
        return if !ref $cgi;

        my $line_limit = 100;
        my $page = $cgi->param('page');

        print $cgi->header;

        open FILE, "<".$config->options_log_file;
        @lines = reverse <FILE>;

        my $count = 0;
        foreach $line (@lines) {
            if($count < (($page*$line_limit)+1)) {
                $count++;
                next;
            }

            print $line;
    
            if($count == ($line_limit+($page*$line_limit))) {
                last;
            } else {
                $count++;
            }
        }
    }

} 

