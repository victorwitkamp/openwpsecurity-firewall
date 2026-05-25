<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pagination;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminPaginator {
	private int $total_items;
	private int $per_page;
	private int $current_page;
	private string $page_slug;
	private string $period;
	private array $query_args;

	public function __construct( int $total_items, int $per_page, int $current_page, string $page_slug, string $period, array $query_args = array() ) {
		$this->total_items  = max( 0, $total_items );
		$this->per_page     = max( 1, $per_page );
		$this->current_page = max( 1, $current_page );
		$this->page_slug    = $page_slug;
		$this->period       = $period;
		$this->query_args   = $query_args;
	}

	public function offset(): int {
		return ( $this->current_page - 1 ) * $this->per_page;
	}

	public function render(): string {
		$total_pages = (int) ceil( $this->total_items / $this->per_page );

		if ( $total_pages <= 1 ) {
			return '';
		}

		$query_args = array_merge(
			array(
				'page' => $this->page_slug,
			),
			$this->query_args
		);

		if ( 'all' !== $this->period ) {
			$query_args['period'] = $this->period;
		}

		$base_url = add_query_arg( $query_args, admin_url( 'admin.php' ) );

		$links = paginate_links(
			array(
				'base'      => add_query_arg( 'paged', '%#%', $base_url ),
				'format'    => '',
				'current'   => $this->current_page,
				'total'     => $total_pages,
				'prev_text' => '&laquo;',
				'next_text' => '&raquo;',
				'type'      => 'list',
			)
		);

		if ( ! is_string( $links ) || $links === '' ) {
			return '';
		}

		return '<div class="tablenav vwfw-pagination"><div class="tablenav-pages">' . $links . '</div></div>';
	}
}
