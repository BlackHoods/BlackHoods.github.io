(function () {
	
	closeRest = function(notElem) {
		var ctn;
		for (var i=0; i<list_ctns.length; i++) {
			ctn = list_ctns[i];
			if (ctn != notElem && ctn.IS_SHOWING) {
				ctn.IS_SHOWING = false;
				ctn.classList.remove(VISIBLE_CLASS);
			}
		}
	}
	
	showHideOpts = function(e) {
		if (!this.IS_SHOWING) {
			this.IS_SHOWING = true;
			this.classList.add(VISIBLE_CLASS);
			closeRest(this);
		} else {
			this.IS_SHOWING = false;
			this.classList.remove(VISIBLE_CLASS);
		}
		
		e.preventDefault();
		e.stopPropagation();
	}
	
	var container_static_name = "fab_ctn";
	var VISIBLE_CLASS = "is-showing-options";
	var list_ctns = [];
	
	for (i=1; i<=2; i++) {
		fab_ctn = document.getElementById(container_static_name + '_' + i);
		if (fab_ctn != null) {
			list_ctns.push(fab_ctn)
			fab_ctn.addEventListener("click", showHideOpts);
		}
	}
	
	document.addEventListener("click", closeRest);
}.call(this));
