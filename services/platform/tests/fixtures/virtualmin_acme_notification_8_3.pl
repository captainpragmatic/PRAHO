	if ($d->{'letsencrypt_email'} == 0 ||
	    $d->{'letsencrypt_email'} == 1 && !$ok) {
		&send_notify_email(
			$from, [$d], $d, $subject, $body, undef,
			undef, undef, undef, undef, undef,
			$d->{'letsencrypt_email_master'} ?
				$gconfig{'webmin_email_to'} : undef);
		}
	&unlock_domain($d);
	}
