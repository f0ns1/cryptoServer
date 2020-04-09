
function hashData() {
	var data = document.getElementById('data');
	var alg = document.getElementById('alg');
	var http = new XMLHttpRequest();
	var url = '/services/hash-service';
	http.open('POST', url, true);
	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('hashData').value = http.responseText;
			document.getElementById('hashTable').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","alg":"' + alg.value + '"}');
	http.send('{"data":"' + data.value + '","alg":"' + alg.value + '"}');

}


function encodeData() {
	var data = document.getElementById('data');
	var alg = document.getElementById('alg');
	var http = new XMLHttpRequest();
	var url = '/services/encode-service';
	http.open('POST', url, true);
	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('encodeData').value = http.responseText;
			document.getElementById('encodeTable').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","alg":"' + alg.value + '"}');
	http.send('{"data":"' + data.value + '","alg":"' + alg.value + '"}');

}

function decodeData() {
	var data = document.getElementById('dataDecode');
	var alg = document.getElementById('algDecode');
	var http = new XMLHttpRequest();
	var url = '/services/decode-service';
	http.open('POST', url, true);
	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('decodeData').value = http.responseText;
			document.getElementById('decodeTable').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","alg":"' + alg.value + '"}');
	http.send('{"data":"' + data.value + '","alg":"' + alg.value + '"}');

}

function signData() {
	var data = document.getElementById('data');
	var priv = document.getElementById('priv');
	// var file = document.getElementById('myfile');
	// alert('file '+file.value);
	// alert('file '+file.files[0]);
	var type = "sign";
	var http = new XMLHttpRequest();
	var url = '/services/sign-jdk-service';
	http.open('POST', url, true);
	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('signData').value = http.responseText;
			document.getElementById('signTable').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","priv":"' + priv.value + '", "type":"'
			+ type + '"}');
	http.send('{"data":"' + data.value + '","priv":"' + priv.value
			+ '", "type":"' + type + '"}');

}

function verifySign() {
	var data = document.getElementById('data');
	var pub = document.getElementById('pub');
	var dataSign = document.getElementById('dataSign');
	var type = "verifySign";
	var http = new XMLHttpRequest();
	var url = '/services/sign-jdk-service';
	http.open('POST', url, true);
	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('verifySignData').value = http.responseText;
			document.getElementById('verifySignTable').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","pub":"' + pub.value + '","dataSign":"'
			+ dataSign.value + '", "type":"' + type + '"}');
	http.send('{"data":"' + data.value + '","pub":"' + pub.value
			+ '","dataSign":"' + dataSign.value + '", "type":"' + type + '"}');

}
function decryptData() {
	var data = document.getElementById('data');
	var pub = document.getElementById('pub');
	var priv = document.getElementById('priv');
	var alg = document.getElementById('alg');
	var certificate = document.getElementById('certificate');
	alert('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '", "certificate":"'
			+ certificate.value + '"}');
	var http = new XMLHttpRequest();
	var url = '/services/decrypt-jdk-service';
	http.open('POST', url, true);
	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('decryptData').value = http.responseText;
			document.getElementById('decryptTable').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '", "certificate":"'
			+ certificate.value + '"}');
	http.send('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '", "certificate":"'
			+ certificate.value + '"}');

}

function decryptEnvelopData() {
	var data = document.getElementById('dataEnv');
	var pub = document.getElementById('pubEnv');
	var priv = document.getElementById('privEnv');
	var alg = document.getElementById('algEnv');
	var certificate = document.getElementById('certificateEnv');
	var http = new XMLHttpRequest();
	var url = '/services/decrypt-bc-service';
	http.open('POST', url, true);
	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('decryptEnvelopDataEnv').value = http.responseText;
			document.getElementById('decryptEnvelopTableEnv').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '", "certificate":"'
			+ certificate.value + '"}');
	http.send('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '", "certificate":"'
			+ certificate.value + '"}');

}

function envEncrypt() {
	var data = document.getElementById('dataEnv');
	var pub = document.getElementById('pubEnv');
	var priv = document.getElementById('privEnv');
	var alg = document.getElementById('algEnv');
	var certificate = document.getElementById('certificateEnv');
	var http = new XMLHttpRequest();
	var url = '/services/encrypt-bc-service';
	http.open('POST', url, true);
	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('envDataOut').value = http.responseText;
			document.getElementById('envTable').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '", "certificate":"'
			+ certificate.value + '"}');
	http.send('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '", "certificate":"'
			+ certificate.value + '"}');

}

function execEncrypt() {
	var data = document.getElementById('data');
	var pub = document.getElementById('pub');
	var priv = document.getElementById('priv');
	var alg = document.getElementById('alg');
	var http = new XMLHttpRequest();
	var url = '/services/encrypt-jdk-service';
	http.open('POST', url, true);

	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('encData').value = http.responseText;
			document.getElementById('encTable').style.display = "block";
		}
	}
	alert('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '"}');
	http.send('{"data":"' + data.value + '","pub":"' + pub.value + '","priv":"'
			+ priv.value + '", "alg":"' + alg.value + '"}');

}

/*******************************************************************************
 * 
 * Certificates js methods
 */
function execCert() {
	var name = document.getElementById('name');
	var validity = document.getElementById('validity');
	var size = document.getElementById('size');
	var http = new XMLHttpRequest();
	var url = '/services/certificates-jdk-service';
	http.open('POST', url, true);
	http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('certB64').value = http.responseText;
			document.getElementById('certTable').style.display = "block";
		}
	}

	http.send('{"name":"' + name.value + '","validity":"' + validity.value
			+ '","size":"' + size.value + '","operation":"certificate"}');
}
function execKeypair() {
	var name = document.getElementById('name');
	var validity = document.getElementById('validity');
	var size = document.getElementById('size');
	var http = new XMLHttpRequest();
	var url = '/services/certificates-jdk-service';
	var params = JSON.parse('{"name":"' + name.value + '","validity":"'
			+ validity.value + '","size":"' + size.value
			+ '","operation":"keypair"}');
	http.open('POST', url, true);

	// Send the proper header information along with the request
	http.setRequestHeader('Content-type', 'application/json');

	http.onreadystatechange = function() {// Call a function when the state
		// changes.
		if (http.readyState == 4) {
			alert(http.responseText);
			document.getElementById('keyB64').value = http.responseText;
			document.getElementById('keyTable').style.display = "block";
		}
	}
	alert('{"name":"' + name.value + '","validity":"' + validity.value
			+ '","size":"' + size.value + '","operation":"keyPair"}')
	http.send('{"name":"' + name.value + '","validity":"' + validity.value
			+ '","size":"' + size.value + '","operation":"keyPair"}');

}
function openNav() {
	document.getElementById("mySidenav").style.width = "250px";
}

function closeNav() {
	document.getElementById("mySidenav").style.width = "0";
}