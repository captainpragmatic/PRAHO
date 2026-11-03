sub modify_status
{
my ($d, $oldd) = @_;
&require_status();

if ($d->{'dom'} ne $oldd->{'dom'} ||
    $d->{'emailto'} ne $oldd->{'emailto'}) {
	# Update HTTP monitor
	&$first_print($text{'save_status'});
	my $serv = &status::get_service($d->{'id'}."_web");
	my $host = &get_domain_http_hostname($d);
	if ($serv) {
		$serv->{'host'} = $host;
		$serv->{'desc'} = "Website $host";
		$serv->{'email'} = &monitor_email($d);
		&status::save_service($serv);
		&$second_print($text{'setup_done'});
		}
	else {
		&$second_print($text{'delete_nostatus'});
		}

	if (&domain_has_ssl_cert($d)) {
		# Update cert monitor
		my $certserv = &status::get_service($d->{'id'}."_sslcert");
		if ($certserv) {
			&$first_print($text{'save_statussslcert'});
			$certserv->{'url'} =
				'https://'.$host.':'.$d->{'web_sslport'}.'/',
			$certserv->{'desc'} = "SSL cert $host";
			$certserv->{'email'} = $d->{'emailto'};
			&status::save_service($certserv);
			&$second_print($text{'setup_done'});
			}
		}

	if (&domain_has_ssl($d)) {
		# Update HTTPS monitor
		&$first_print($text{'save_statusssl'});
		my $serv = &status::get_service($d->{'id'}."_ssl");
		if ($serv) {
			$serv->{'host'} = $host;
			$serv->{'desc'} = "Website $host (SSL)";
			$serv->{'email'} = $d->{'emailto'};
			&status::save_service($serv);
			&$second_print($text{'setup_done'});
			}
		else {
			&$second_print($text{'delete_nostatus'});
			}
		}
	}

if (&domain_has_ssl($d) && !&domain_has_ssl($oldd)) {
