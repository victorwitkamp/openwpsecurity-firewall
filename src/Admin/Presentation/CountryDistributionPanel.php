<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Presentation;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CountryDistributionPanel {
	private const COLORS = array(
		'#0f766e',
		'#2563eb',
		'#ea580c',
		'#dc2626',
		'#7c3aed',
		'#0891b2',
		'#65a30d',
		'#ca8a04',
	);

	public function render( array $countries, string $title, string $center_label ): void {
		$total = 0;

		foreach ( $countries as $country ) {
			$total += (int) ( $country['total'] ?? 0 );
		}

		?>
		<div class="vwfw-panel vwfw-country-panel">
			<h3><?php echo esc_html( $title ); ?></h3>
			<?php if ( $total < 1 ) : ?>
				<p class="description">No country data is available for this period.</p>
			<?php else : ?>
				<?php
				$segments = array();
				$offset   = 0.0;
				?>
				<div class="vwfw-country-layout">
					<div class="vwfw-country-donut-shell">
						<?php foreach ( $countries as $index => $country ) : ?>
							<?php
							$count      = (int) $country['total'];
							$percentage = $total > 0 ? ( $count / $total ) * 100 : 0;
							$start      = $offset;
							$offset    += $percentage;
							$color      = self::COLORS[ $index % count( self::COLORS ) ];
							$segments[] = array(
								'color' => $color,
								'start' => round( $start, 2 ),
								'end'   => round( min( 100, $offset ), 2 ),
							);
							?>
						<?php endforeach; ?>
						<div class="vwfw-country-donut" data-segments="<?php echo esc_attr( (string) wp_json_encode( $segments ) ); ?>">
							<div class="vwfw-country-donut-center">
								<strong><?php echo esc_html( number_format_i18n( $total ) ); ?></strong>
								<span><?php echo esc_html( $center_label ); ?></span>
							</div>
						</div>
					</div>
					<div class="vwfw-country-legend">
						<?php foreach ( $countries as $index => $country ) : ?>
							<?php
							$count      = (int) $country['total'];
							$percentage = $total > 0 ? round( ( $count / $total ) * 100, 1 ) : 0;
							$color      = self::COLORS[ $index % count( self::COLORS ) ];
							$label      = trim( (string) $country['country_code'] . ' ' . (string) $country['country_name'] );
							?>
							<div class="vwfw-country-legend-item">
								<span class="vwfw-country-swatch" data-color="<?php echo esc_attr( $color ); ?>"></span>
								<span class="vwfw-country-name"><?php echo esc_html( $label ); ?></span>
								<span class="vwfw-country-meta"><?php echo esc_html( number_format_i18n( $count ) . ' (' . $percentage . '%)' ); ?></span>
							</div>
						<?php endforeach; ?>
					</div>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}
}
