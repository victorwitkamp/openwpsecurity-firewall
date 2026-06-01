<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

use VictorWitkamp\OpenWPSecurity\Core\Logging\EventWriter as CoreEventWriter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventWriter extends CoreEventWriter {
	public function __construct( EventTable $event_table, EventSchema $event_schema ) {
		parent::__construct( $event_table, $event_schema->table_schema() );
	}
}
