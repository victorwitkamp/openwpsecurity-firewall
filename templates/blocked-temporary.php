<?php

declare(strict_types=1);
?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?php echo esc_html( isset( $title ) && $title !== '' ? (string) $title : 'Temporary Block' ); ?></title>
	<?php wp_print_styles( 'openwpsecurity-firewall-runtime' ); ?>
</head>
<body class="vwfw-runtime-page vwfw-runtime-page--temporary">
	<div class="vwfw-runtime-shell">
		<div class="vwfw-runtime-box">
			<h1 class="vwfw-runtime-title"><?php echo esc_html( isset( $title ) && $title !== '' ? (string) $title : 'Access temporarily blocked' ); ?></h1>
			<p class="vwfw-runtime-text"><?php echo esc_html( isset( $message ) && $message !== '' ? (string) $message : 'Too many requests were detected from this IP address. Access is temporarily blocked.' ); ?></p>
			<p class="vwfw-runtime-text"><span class="vwfw-runtime-highlight">Try again in <?php echo esc_html( (string) $minutes_left ); ?> minute(s).</span></p>
			<?php if ( ! empty( $lockout_expires ) ) : ?>
				<p class="vwfw-runtime-text">The lockout expires at <?php echo esc_html( get_date_from_gmt( gmdate( 'Y-m-d H:i:s', (int) $lockout_expires ), 'Y-m-d H:i:s' ) ); ?>.</p>
			<?php endif; ?>
			<p class="vwfw-runtime-text"><a class="vwfw-runtime-link" href="<?php echo esc_url( home_url( '/' ) ); ?>">Return to the homepage</a></p>
			<div class="vwfw-runtime-meta">IP address: <?php echo esc_html( (string) $ip ); ?></div>
		</div>
	</div>
	<?php wp_print_footer_scripts(); ?>
</body>
</html>
