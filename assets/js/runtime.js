(function () {
	function bindDebugBarHide() {
		document.addEventListener('click', function (event) {
			var hideButton = event.target.closest('[data-vwfw-debug-hide]');

			if (!hideButton) {
				return;
			}

			event.preventDefault();
			event.stopPropagation();

			var debugBar = hideButton.closest('.vwfw-debug-bar');

			if (debugBar) {
				debugBar.remove();
			}
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', bindDebugBarHide);
		return;
	}

	bindDebugBarHide();
})();
