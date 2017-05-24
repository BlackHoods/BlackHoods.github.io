(function () {
	showOpts = function(e) {
		
		var processClick = function (evt) {
			if (e !== evt) {
				for (var i = 0; i < list_ctns.length; i++) {
					if (list_ctns[i].IS_SHOWING) {
						list_ctns[i].classList.remove(VISIBLE_CLASS);
						list_ctns[i].IS_SHOWING = false;
						document.removeEventListener("click", processClick);
					}
				}
				
			}
		};
		
		if (!this.IS_SHOWING) {
			this.IS_SHOWING = true;
			this.classList.add(VISIBLE_CLASS);
			document.addEventListener("click", processClick);
		}
	};
	
	var container_static_name = "fab_ctn";
	var VISIBLE_CLASS = "is-showing-options";
	var list_ctns = [];
	
	for (i=1; i<=2; i++) {
		fab_ctn = document.getElementById(container_static_name + '_' + i);
		
		if (fab_ctn != null) {
			list_ctns.push(fab_ctn)
			fab_ctn.addEventListener("click", showOpts);
		}
	}
	
}.call(this));
