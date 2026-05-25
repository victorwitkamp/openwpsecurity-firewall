(function () {
	function parseJsonAttribute(element, attributeName) {
		var rawValue = element.getAttribute(attributeName);

		if (!rawValue) {
			return [];
		}

		try {
			return JSON.parse(rawValue);
		} catch (error) {
			return [];
		}
	}

	function renderFailedLoginTrends() {
		var charts = document.querySelectorAll('.vwfw-chart[data-series]');

		charts.forEach(function (chart) {
			var series = parseJsonAttribute(chart, 'data-series');

			if (!Array.isArray(series) || !series.length) {
				chart.innerHTML = '<p>No failed login data for this period.</p>';
				return;
			}

			var maxValue = Math.max.apply(
				null,
				series.map(function (item) {
					return Number(item.value || 0);
				})
			);
			var bars = document.createElement('div');
			bars.className = 'vwfw-bars';

			series.forEach(function (item) {
				var height = maxValue > 0 ? Math.max(6, Math.round((Number(item.value || 0) / maxValue) * 140)) : 6;
				var barWrap = document.createElement('div');
				var bar = document.createElement('div');
				var label = document.createElement('span');

				barWrap.className = 'vwfw-bar-wrap';
				bar.className = 'vwfw-bar';
				bar.style.height = height + 'px';
				label.textContent = String(item.label || '');

				barWrap.appendChild(bar);
				barWrap.appendChild(label);
				bars.appendChild(barWrap);
			});

			chart.replaceChildren(bars);
		});
	}

	function renderCountryDonuts() {
		var donuts = document.querySelectorAll('.vwfw-country-donut[data-segments]');
		var swatches = document.querySelectorAll('.vwfw-country-swatch[data-color]');

		donuts.forEach(function (donut) {
			var segments = parseJsonAttribute(donut, 'data-segments');

			if (!Array.isArray(segments) || !segments.length) {
				return;
			}

			var gradientStops = segments
				.map(function (segment) {
					return [segment.color, Number(segment.start).toFixed(2) + '%', Number(segment.end).toFixed(2) + '%'].join(' ');
				})
				.join(', ');

			donut.style.background = 'conic-gradient(' + gradientStops + ')';
		});

		swatches.forEach(function (swatch) {
			swatch.style.background = String(swatch.getAttribute('data-color') || '');
		});
	}

	function initializeAdminAssets() {
		renderFailedLoginTrends();
		renderCountryDonuts();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initializeAdminAssets);
		return;
	}

	initializeAdminAssets();
})();
