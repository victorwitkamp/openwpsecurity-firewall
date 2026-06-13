<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling;

use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FrontendPageVisitLogger {
	private EventLogger $event_logger;
	private RequestContext $request_context;

	public function __construct( EventLogger $event_logger, RequestContext $request_context ) {
		$this->event_logger    = $event_logger;
		$this->request_context = $request_context;
	}

	public function record( string $ip ): void {
		$this->event_logger->log(
			'page_visit',
			$ip,
			'',
			array(
				'details' => array(
					'method'       => $this->request_context->current_method(),
					'request_type' => 'frontend_page',
				),
			)
		);
	}
}
