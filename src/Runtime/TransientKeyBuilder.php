<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Runtime;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TransientKeyBuilder {
	public function captcha_failure_history( string $ip_address ): string {
		return 'vwfw_captcha_failures_' . md5( $ip_address );
	}

	public function captcha_challenge( string $token ): string {
		return 'vwfw_captcha_challenge_' . $token;
	}

	public function request_handling_rate_limit_hits( string $request_type, string $ip_address ): string {
		return 'vwfw_request_hits_' . $request_type . '_' . md5( $ip_address );
	}

	public function request_handling_temporary_block( string $ip_address ): string {
		return 'vwfw_request_temporary_block_' . md5( $ip_address );
	}
}
