<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Runtime;

use DI\ContainerBuilder;
use Psr\Container\ContainerInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WordPressIntegration {
	private ?ContainerInterface $container = null;

	private ?ContainerDefinitions $container_definitions = null;

	public function activate(): void {
		$this->plugin()->activate();
	}

	public function deactivate(): void {
		$this->plugin()->deactivate();
	}

	public function initialize_runtime(): void {
		$this->plugin()->initialize_runtime();
	}

	private function plugin(): Plugin {
		$plugin = $this->container()->get( Plugin::class );

		if ( ! $plugin instanceof Plugin ) {
			throw new \RuntimeException( 'Firewall plugin service did not resolve correctly.' );
		}

		return $plugin;
	}

	private function container(): ContainerInterface {
		if ( null !== $this->container ) {
			return $this->container;
		}

		$builder = new ContainerBuilder();
		$builder->useAutowiring( true );
		$builder->useAttributes( false );
		$builder->addDefinitions( $this->container_definitions()->definitions() );
		$this->container = $builder->build();

		return $this->container;
	}

	private function container_definitions(): ContainerDefinitions {
		if ( null === $this->container_definitions ) {
			$this->container_definitions = new ContainerDefinitions();
		}

		return $this->container_definitions;
	}
}
