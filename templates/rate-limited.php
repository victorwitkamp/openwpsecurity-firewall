<!doctype html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?php echo esc_html( (string) $title ); ?></title>
	<?php wp_print_styles( 'openwpsecurity-firewall-runtime' ); ?>
</head>
<body class="vwfw-runtime-page <?php echo ! empty( $show_captcha ) ? 'vwfw-runtime-page--captcha' : 'vwfw-runtime-page--rate-limited'; ?>">
	<div class="vwfw-runtime-shell">
		<div class="vwfw-runtime-box">
			<h1 class="vwfw-runtime-title"><?php echo esc_html( (string) $title ); ?></h1>
			<p class="vwfw-runtime-text"><?php echo esc_html( (string) $message ); ?></p>
			<?php if ( ! empty( $retry_after_seconds ) ) : ?>
				<p class="vwfw-runtime-text">Retry after approximately <?php echo esc_html( (string) max( 1, (int) ceil( (int) $retry_after_seconds / 60 ) ) ); ?> minute(s).</p>
			<?php endif; ?>
			<?php if ( ! empty( $error ) ) : ?>
				<div class="vwfw-runtime-error"><?php echo esc_html( (string) $error ); ?></div>
			<?php endif; ?>
			<?php if ( ! empty( $show_captcha ) ) : ?>
				<form method="post">
					<?php wp_nonce_field( 'vwfw_captcha_submit', 'vwfw_nonce' ); ?>
					<input type="hidden" name="vwfw_captcha_submit" value="1">
					<input type="hidden" name="vwfw_token" value="<?php echo esc_attr( (string) $token ); ?>">
					<label class="vwfw-runtime-label" for="vwfw-answer">What is <?php echo esc_html( (string) $a ); ?> + <?php echo esc_html( (string) $b ); ?>?</label>
					<input id="vwfw-answer" class="vwfw-runtime-input" name="vwfw_answer" type="text" inputmode="numeric" autocomplete="off" required>
					<button class="vwfw-runtime-button" type="submit">Continue</button>
				</form>
				<p class="vwfw-runtime-meta">Shared captcha is active for frontend pages and the WP Login page while their rate limits are exceeded.</p>
			<?php endif; ?>
			<div class="vwfw-runtime-meta">IP address: <?php echo esc_html( (string) $ip ); ?></div>
		</div>
	</div>
	<?php do_action( 'openwpsecurity_firewall_render_debug_bar' ); ?>
	<?php wp_print_footer_scripts(); ?>
</body>
</html>
