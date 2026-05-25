<!doctype html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?php echo esc_html( isset( $title ) && $title !== '' ? (string) $title : 'Access Blocked' ); ?></title>
	<?php wp_print_styles( 'openwpsecurity-firewall-runtime' ); ?>
</head>
<body class="vwfw-runtime-page vwfw-runtime-page--permanent">
	<div class="vwfw-runtime-shell">
		<div class="vwfw-runtime-box">
			<h1 class="vwfw-runtime-title"><?php echo esc_html( isset( $title ) && $title !== '' ? (string) $title : 'Access blocked' ); ?></h1>
			<p class="vwfw-runtime-text"><?php echo esc_html( isset( $message ) && $message !== '' ? (string) $message : 'This IP address has been permanently blocked by the firewall.' ); ?></p>
			<p class="vwfw-runtime-text"><?php echo esc_html( isset( $message_secondary ) && $message_secondary !== '' ? (string) $message_secondary : 'If you believe this is incorrect, contact the site administrator and include the IP address shown below.' ); ?></p>
			<p class="vwfw-runtime-text"><a class="vwfw-runtime-link" href="<?php echo esc_url( home_url( '/' ) ); ?>">Return to the homepage</a></p>
			<div class="vwfw-runtime-meta">IP address: <?php echo esc_html( (string) $ip ); ?></div>
		</div>
	</div>
	<?php do_action( 'openwpsecurity_firewall_render_debug_bar' ); ?>
	<?php wp_print_footer_scripts(); ?>
</body>
</html>
