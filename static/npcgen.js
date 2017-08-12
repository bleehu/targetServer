(function(){

	window.onload = function(){
		setInterval(function(){
			tbox = document.getElementById("comment");
			comment = tbox.innerHTML;
			comment = comment.replace("<","");
			comment = comment.replace(">", "");
			tbox.innerHTML = comment;
			console.log("tick");
		}, 5);
		
	}
}

})());