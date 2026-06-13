<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;

final class SecurityIncidentDetailsFormatter {
	private EventReportFormatter $event_report_formatter;

	public function __construct( EventReportFormatter $event_report_formatter ) {
		$this->event_report_formatter = $event_report_formatter;
	}

	public function request_type_label( string $request_type, array $details ): string {
		if ( '' !== $request_type ) {
			return $this->event_report_formatter->request_type_label( $request_type );
		}

		if ( ! empty( $details['request_type'] ) ) {
			return $this->event_report_formatter->request_type_label( (string) $details['request_type'] );
		}

		return '';
	}

	public function details( string $event_type, array $details ): string {
		if ( 'captcha_required' === $event_type ) {
			$message = sprintf(
				'Rate limit reached on %s at %d hits in %d seconds. A shared captcha challenge was rendered.',
				$this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ),
				(int) ( $details['hit_count'] ?? 0 ),
				(int) ( $details['rate_limit_window_seconds'] ?? 0 )
			);

			if ( isset( $details['captcha_challenge_count'], $details['captcha_challenges_before_temporary_block'] ) && (int) $details['captcha_challenges_before_temporary_block'] > 0 ) {
				$message .= sprintf(
					' Unsolved challenge pages: %d/%d.',
					(int) $details['captcha_challenge_count'],
					(int) $details['captcha_challenges_before_temporary_block']
				);
			}

			return $message;
		}

		if ( 'captcha_failed' === $event_type ) {
			return sprintf(
				'Captcha answer did not match the stored challenge. Failures: %d/%d in %d minute(s).',
				(int) ( $details['captcha_failure_count'] ?? 0 ),
				(int) ( $details['captcha_failure_threshold'] ?? 0 ),
				(int) ( $details['captcha_failure_window_minutes'] ?? 0 )
			);
		}

		if ( 'captcha_passed' === $event_type ) {
			return sprintf(
				'Captcha solved successfully. Bypass cookie active for %d minute(s).',
				(int) ( $details['captcha_pass_minutes'] ?? 0 )
			);
		}

		if ( 'permanent_ban_created' === $event_type ) {
			return $this->permanent_ban_details( $details );
		}

		if ( 'request_rate_limited' === $event_type ) {
			return $this->rate_limit_details( $details );
		}

		if ( 'request_temporary_block_created' === $event_type ) {
			return $this->temporary_ban_created_details( $details );
		}

		if ( 'request_temporarily_blocked' === $event_type ) {
			$message = 'An active Firewall temporary ban denied this request.';

			if ( ! empty( $details['trigger_request_type'] ) ) {
				$message .= ' Triggered by ' . $this->event_report_formatter->request_type_label( (string) $details['trigger_request_type'] ) . '.';
			}

			if ( isset( $details['active_block_denial_count'], $details['active_block_denials_before_permanent_ban'] ) && (int) $details['active_block_denials_before_permanent_ban'] > 0 ) {
				$message .= sprintf(
					' Active-block denials: %d/%d.',
					(int) $details['active_block_denial_count'],
					(int) $details['active_block_denials_before_permanent_ban']
				);
			}

			return $message;
		}

		return '';
	}

	private function permanent_ban_details( array $details ): string {
		if ( 'request_handling' !== (string) ( $details['source'] ?? '' ) ) {
			return sprintf(
				'%s via %s after %d lockout(s).',
				(string) ( $details['reason'] ?? 'Permanent ban created' ),
				$this->event_report_formatter->ban_source_label( (string) ( $details['source'] ?? 'unknown source' ) ),
				(int) ( $details['lockout_count'] ?? 0 )
			);
		}

		if ( 'active_temporary_block_denials' === (string) ( $details['reason'] ?? '' ) ) {
			return sprintf(
				'Request handling permanently banned this IP after %d denied request(s) during an active temporary ban triggered by %s.',
				(int) ( $details['active_block_denial_count'] ?? 0 ),
				$this->event_report_formatter->request_type_label( (string) ( $details['trigger_request_type'] ?? '' ) )
			);
		}

		if ( 'captcha_challenge_volume' === (string) ( $details['reason'] ?? '' ) ) {
			return sprintf(
				'Request handling permanently banned this IP after repeated unsolved captcha challenge pages on %s and %d temporary ban(s).',
				$this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ),
				(int) ( $details['temporary_block_count'] ?? 0 )
			);
		}

		return sprintf(
			'%s via request handling on %s after %d temporary ban(s).',
			(string) ( $details['reason'] ?? 'Permanent ban created' ),
			$this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ),
			(int) ( $details['temporary_block_count'] ?? 0 )
		);
	}

	private function rate_limit_details( array $details ): string {
		$message = sprintf(
			'%d hits in %d seconds against a threshold of %d.',
			(int) ( $details['hit_count'] ?? 0 ),
			(int) ( $details['rate_limit_window_seconds'] ?? ( $details['window_seconds'] ?? 0 ) ),
			(int) ( $details['rate_limit_threshold'] ?? ( $details['threshold'] ?? 0 ) )
		);

		$response_action_messages = array(
			'captcha_page'    => ' A shared captcha challenge handled the response.',
			'rate_limit_page' => ' A 429 rate-limit page handled the response.',
			'message_only'    => ' The endpoint returned a 429 firewall message without creating a temporary ban.',
			'temporary_block' => ' Request handling escalated immediately into a temporary ban.',
		);
		$response_action          = (string) ( $details['response_action'] ?? '' );

		if ( isset( $response_action_messages[ $response_action ] ) ) {
			$message .= $response_action_messages[ $response_action ];
		}

		if ( ! empty( $details['temporary_block_enabled'] ) ) {
			$message .= ' Temporary bans were enabled for this request.';
		}

		return $message;
	}

	private function temporary_ban_created_details( array $details ): string {
		$reason = (string) ( $details['reason'] ?? '' );

		if ( 'captcha_failed' === $reason ) {
			$message = sprintf(
				'%d failed captcha answer(s) in %d minute(s) created a temporary ban for %d minute(s).',
				(int) ( $details['captcha_failure_count'] ?? 0 ),
				(int) ( $details['captcha_failure_window_minutes'] ?? 0 ),
				(int) ( $details['temporary_block_minutes'] ?? 0 )
			);
		} elseif ( 'captcha_challenge_volume' === $reason ) {
			$message = sprintf(
				'%d unsolved captcha challenge page(s) in %d seconds created a temporary ban for %d minute(s).',
				(int) ( $details['captcha_challenge_count'] ?? 0 ),
				(int) ( $details['captcha_challenge_window_seconds'] ?? 0 ),
				(int) ( $details['temporary_block_minutes'] ?? 0 )
			);
		} else {
			$message = sprintf(
				'%d hits in %d seconds against a threshold of %d created a temporary ban for %d minute(s).',
				(int) ( $details['hit_count'] ?? 0 ),
				(int) ( $details['rate_limit_window_seconds'] ?? 0 ),
				(int) ( $details['rate_limit_threshold'] ?? 0 ),
				(int) ( $details['temporary_block_minutes'] ?? 0 )
			);
		}

		if ( isset( $details['temporary_block_count'], $details['temporary_blocks_before_permanent_ban'] ) ) {
			$message .= sprintf(
				' Temporary bans: %d/%d.',
				(int) $details['temporary_block_count'],
				(int) $details['temporary_blocks_before_permanent_ban']
			);
		}

		return $message;
	}
}
