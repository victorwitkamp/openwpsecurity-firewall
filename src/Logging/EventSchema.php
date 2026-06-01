<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchemaInstaller;
use VictorWitkamp\OpenWPSecurity\Core\Logging\EventSchema as CoreEventSchema;
use VictorWitkamp\OpenWPSecurity\Core\Logging\EventTableSchemaFactory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventSchema extends CoreEventSchema {
	private const DB_VERSION        = '1.2.1';
	private const DB_VERSION_OPTION = 'openwpsecurity_firewall_db_version';

	public function __construct( TableSchemaInstaller $schema_installer, EventTableSchemaFactory $schema_factory, EventTable $event_table ) {
		parent::__construct(
			$schema_installer,
			$schema_factory->create( $event_table, self::DB_VERSION_OPTION, self::DB_VERSION )
		);
	}
}
