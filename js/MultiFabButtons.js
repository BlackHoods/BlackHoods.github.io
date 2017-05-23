(function () {
	var div = document.getElementById("MemberCnt");
	var button_static_name = "fab_btn";
	var container_static_name = "fab_ctn";
	for ( i = 0 ; i < 2 ; i++){
		div.innerHTML =
			'<!-- Actual buttons that fly out -->\n' +
				            '<div id="fab_ctn' + i + '" class="mdl-button--fab_flinger-container">\n' +
				                
				                '<button id="fab_btn' + i + '" class="mdl-button mdl-js-ripple-effect mdl-js-button mdl-button--fab mdl-color--accent">\n' +
				                    '<i class="icon ion-android-add mdl-color-text--white" role="presentation"></i>\n' +
				                    '<span class="visuallyhidden">add</span>\n' +
				                '</button>\n' +
				                
				                '<div class="mdl-button--fab_flinger-options">\n' +
				                    '<a href="{{ .RelPermalink }}">\n' +
				                        '<button id="about" class="mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect mdl-color--primary" title="About Me">'\n +
				                            '<i class="icon ion-person mdl-color-text--white" role="presentation"></i>\n' +
				                        '</button>\n' +
				                    '</a>\n' +
				                    
				                    '<a href="/project">\n' +
				                        '<button id="projects" class="mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect mdl-color--primary" title="My Projects">\n' +
				                            '<i class="icon ion-code mdl-color-text--white" role="presentation"></i>\n' +
				                        '</button>\n' +
				                    '</a>\n' +

									'<a href=".Params.linkedin">\n' +
				                        '<button id="l" class="mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect mdl-color--primary" title="My Projects">\n' +
				                            '<i class="icon ion-social-linkedin mdl-color-text--white" role="presentation"></i>\n' +
				                    '</button>\n' +
				                    '</a>\n' +
				                    
				                    '<a href="mailto:{{ .Params.email }}?subject=Hi">\n' +
				                        '<button id="email" class="mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect mdl-color--primary" title="Email Me">\n' +
				                            '<i class="icon ion-email mdl-color-text--white" role="presentation"></i>\n' +
				                        '</button>\n' +
				                    '</a>\n' +
				                '</div>\n' +
				            '</div>\n';
	}
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
	for (i = 0 ; i < 2 ; i++){
		var VISIBLE_CLASS = "is-showing-options";
			fab_btn  = document.getElementById(button_static_name + i);
			fab_ctn  = document.getElementById(container_static_name + i);
		
		fab_btn.addEventListener("click", showOpts);
	}
}.call(this));
