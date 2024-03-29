<?php
/*
 * PHP Armor 1.2.2017.08
 * Copyleft 2014.03, Nikolay Mihaylov
 * History:
 *      2014.03 - initial version
 *      2014.04 - virtualized as a function, to prevent registered variables overwrite.
 *      2015.02 - add fancybox fix.
 *      2015.03 - add nginx X_REAL_IP support.
 *      2016.10 - add CF HTTPS support.
 *      2017.08 - fix array parameters
 *      2023.01 - fix symphony _fragment
 */

function armor_1234567890_abc(){
	$permited_proxy = array("127.0.0.1");

	foreach($_REQUEST as $key => $data){
		if (is_array($data))
			continue;

		$data = strtolower($data);

		if (strpos($data, "base64_") !== false)
			exit;

		if (strpos($data, "union") !== false && strpos($data, "select") !== false)
			exit;

		if (strpos($data, "sleep(") !== false)
			exit;
	}

	// http://blog.sucuri.net/2015/02/analysis-of-the-fancybox-for-wordpress-vulnerability.html
	if (isset($_REQUEST["action"]) && $_REQUEST["action"] == "update" && isset($_REQUEST["mfbfw"]))
		exit;

	// https://www.ambionics.io/blog/symfony-secret-fragment
	if (
		(isset($_SERVER["REQUEST_URI" ]) && strpos($_SERVER["REQUEST_URI" ], "/_fragment") !== false )
	)
		exit;

	// fix REMOTE_ADDR
	if (isset($_SERVER["HTTP_X_REAL_IP"]) && in_array($_SERVER["REMOTE_ADDR"], $permited_proxy))
		$_SERVER["REMOTE_ADDR"] = $_SERVER["HTTP_X_REAL_IP"];

	if (isset($_SERVER["HTTP_CF_CONNECTING_IP"]))
		$_SERVER["REMOTE_ADDR"] = $_SERVER["HTTP_CF_CONNECTING_IP"];

	// SSL ceritificate
	foreach( array( 'HTTP_CF_VISITOR', 'HTTP_X_FORWARDED_PROTO', 'HTTP_X_FORWARDED_PROTOCOL' ) as $option ) {
		if ( isset( $_SERVER[ $option ] ) && ( strpos( $_SERVER[ $option ], 'https' ) !== false ) ) {
			$_SERVER[ 'HTTPS' ] = 'on';
			break;
		}
	}
}

armor_1234567890_abc();

#require __DIR__ . "/mysql_mysqli.inc.php";

