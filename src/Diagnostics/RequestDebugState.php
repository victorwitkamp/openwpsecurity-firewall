<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Diagnostics;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestDebugState {
	private array $state = array(
		'conditions' => array(),
	);

	public function merge( string $section, array $values ): void {
		$current                 = isset( $this->state[ $section ] ) && is_array( $this->state[ $section ] ) ? $this->state[ $section ] : array();
		$this->state[ $section ] = array_merge( $current, $values );
	}

	public function set( string $section, $value ): void {
		$this->state[ $section ] = $value;
	}

	public function add_condition( string $condition ): void {
		if ( '' === $condition ) {
			return;
		}

		if ( ! in_array( $condition, $this->state['conditions'], true ) ) {
			$this->state['conditions'][] = $condition;
		}
	}

	public function all(): array {
		return $this->state;
	}
}
