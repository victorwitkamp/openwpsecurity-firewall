<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Runtime;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\StreamFactory;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use VictorWitkamp\OpenWPSecurity\Core\Http\WordPressServerRequestFactory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ContainerDefinitions {
	public function definitions(): array {
		return array(
			ServerRequestInterface::class   => static function ( WordPressServerRequestFactory $factory ): ServerRequestInterface {
				return $factory->create();
			},
			ResponseFactoryInterface::class => static function (): ResponseFactoryInterface {
				return new ResponseFactory();
			},
			StreamFactoryInterface::class   => static function (): StreamFactoryInterface {
				return new StreamFactory();
			},
		);
	}
}
