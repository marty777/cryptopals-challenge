<?php
/*
	This is the web server component for Set 4 Challenge 31.
	Given the GET parameters 'file' and 'signature', generate
	an HMAC for the file string and compare it with the
	provided signature. Add an artificial delay during
	the string comparison to allow a timing leak.
	
	Requires PHP 5.4 or higher
*/
function insecure_compare($a, $b) {
	for($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
		if($a[$i] != $b[$i]) {
			return false;
		}
		usleep(50000); // 50 microseconds
	}
	 if(strlen($a) != strlen($b)) {
		 return false;
	 }
	return true;
}

if(!isset($_GET['file']) || !isset($_GET['signature'])) {
	http_response_code(500);
	die("Not OK");
}

// From Cato, a Tragedy by Joseph Addison
$key = "The soul, secured in her existence, smiles
At the drawn dagger, and defies its point.
The stars shall fade away, the sun himself
Grow dim with age, and nature sink in years;
But thou shalt flourish in immortal youth,
Unhurt amidst the war of elements,
The wreck of matter, and the crush of worlds.";

$hmac = hash_hmac("sha1", $_GET['file'], $key); // was using sha256, but the timing attack is slow enough already.
// a 40 character hash takes forever to get through.
$hmac = substr($hmac, 0, 16);

if(!insecure_compare($hmac, $_GET['signature'])) {
	http_response_code(500);
	die($hmac);
}
else {
	die("OK"); // defaults to status 200
}

?>