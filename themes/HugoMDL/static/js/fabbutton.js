(function () {
showOpts = function(e) {
		    console.log('clicked!');
		    var processClick = function (evt) {
		    if (e !== evt) {
		        fab_ctn.classList.remove(VISIBLE_CLASS);
		        fab_ctn.IS_SHOWING = false;
		        document.removeEventListener("click", processClick);
		    }
		    };
		    if (!fab_ctn.IS_SHOWING) {
		    fab_ctn.IS_SHOWING = true;
		    fab_ctn.classList.add(VISIBLE_CLASS);
		    document.addEventListener("click", processClick);
		    }
		};
var button_static_name = "fab_btn";
var container_static_name = "fab_ctn";
	var VISIBLE_CLASS = "is-showing-options";
		fab_btn  = document.getElementById(button_static_name );
		fab_ctn  = document.getElementById(container_static_name);
		
	fab_btn.addEventListener("click", showOpts);

}.call(this));
