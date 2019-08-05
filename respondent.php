<?php

/**
Code Notes:
1- unfinished elements are <strike>'n
**/

/**
TODO:
+ ✅add redirect code
# allow all via get/post/cookie
# make a proper args handler
+ content-type header option to payload generator
+ arbitrary headers to payload generator
+ add raw parameter processing
+ add random response feature
+ add random attack payload via §sql or §xss
+ logging
# refactor stuff into functions
# sort out how/where to decide if x-powered-by headers should stay/go
# fully implement all auth-types. But it involves reading RFCs and i don't wanna.
-

**/

//Basically (get|has|set)Param in Zend
function getParam($key){
    switch (true) {
        case isset($_GET[$key]):
            return $_GET[$key];
        case isset($_POST[$key]):
            return $_POST[$key];
        case isset($_COOKIE[$key]):
            return $_COOKIE[$key];
        default:
            return null;
    }    
}
function hasParam($key){
    switch (true) {
        case isset($_GET[$key]):
            return true;
        case isset($_POST[$key]):
            return true;
        case isset($_COOKIE[$key]):
            return true;
        default:
            return null;
    }    
}
function setParam($key, $value){    
	$_GET[$key] = $value;
	$_POST[$key] = $value;
	$_COOKIE[$key] = $value;
} 

function cleanupThenDie($err){

	foreach (headers_list() as &$header) {
		$headername = explode(":", $header);
		if (function_exists('header_remove')){
			header_remove($headername[0]);
		}
		else{
			header($headername[0] . ':');
		}
	}
	header('HTTP/1.1 500 Internal Server Error');
	die($err);
}

function advanced_http_response_code($protocol, $code, $text) {
	#set protocol
	if ($protocol !== NULL){
        if (strtoupper($protocol) == 'HTTP/1.0' || strtoupper($protocol) == 'HTTP/1.1'){
            $header = strtoupper($protocol);
        }
        else{
            $header = $protocol;
        }
	}
	else{
		$header = (isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0');
	}

	#set status-code
    if ($code !== NULL) {
        $header .= ' ' . $code;
    	# TODO: add § XSS injection payload marker here.
    	$header .= ($text !== NULL ? ' ' . $text : ' ' . getTextFromCode($code));
    }
	else{
		$header .= ' ' . (isset($GLOBALS['http_response_code']) ? $GLOBALS['http_response_code'] : 200);
		$header .= ($text !== NULL ? ' ' . $text : ' ' . 'OK');
	}
	return $header;
}

function getTextFromCode($code){
    switch ($code) {
        case 100: $text = 'Continue'; break;
        case 101: $text = 'Switching Protocols'; break;
        case 200: $text = 'OK'; break;
        case 201: $text = 'Created'; break;
        case 202: $text = 'Accepted'; break;
        case 203: $text = 'Non-Authoritative Information'; break;
        case 204: $text = 'No Content'; break;
        case 205: $text = 'Reset Content'; break;
        case 206: $text = 'Partial Content'; break;
        case 300: $text = 'Multiple Choices'; break;
        case 301: $text = 'Moved Permanently'; break;
        case 302: $text = 'Moved Temporarily'; break;
        case 303: $text = 'See Other'; break;
        case 304: $text = 'Not Modified'; break;
        case 305: $text = 'Use Proxy'; break;
        case 400: $text = 'Bad Request'; break;
        case 401: $text = 'Unauthorized'; break;
        case 402: $text = 'Payment Required'; break;
        case 403: $text = 'Forbidden'; break;
        case 404: $text = 'Not Found'; break;
        case 405: $text = 'Method Not Allowed'; break;
        case 406: $text = 'Not Acceptable'; break;
        case 407: $text = 'Proxy Authentication Required'; break;
        case 408: $text = 'Request Time-out'; break;
        case 409: $text = 'Conflict'; break;
        case 410: $text = 'Gone'; break;
        case 411: $text = 'Length Required'; break;
        case 412: $text = 'Precondition Failed'; break;
        case 413: $text = 'Request Entity Too Large'; break;
        case 414: $text = 'Request-URI Too Large'; break;
        case 415: $text = 'Unsupported Media Type'; break;
        #save418
        case 418: $text = 'I\'m A Teapot'; break; 
        case 500: $text = 'Internal Server Error'; break;
        case 501: $text = 'Not Implemented'; break;
        case 502: $text = 'Bad Gateway'; break;
        case 503: $text = 'Service Unavailable'; break;
        case 504: $text = 'Gateway Time-out'; break;
        case 505: $text = 'HTTP Version not supported'; break;
        default:
            return 'OK';
        break;
    }
    return $text;
 }

function getAuthHeaderFromAuthType($auth){
	switch ($auth) {
			#[RFC7617]
        case 'basic': $text = 'WWW-Authenticate: Basic realm="WallyWorld"'; break;
        	#[RFC6750]
        case 'bearer': $text = 'WWW-Authenticate: Bearer realm="WallyWorld"'; break;
        	#[RFC7616]
        case 'digest': $text = 'WWW-Authenticate: Digest realm="http-auth@example.org",qop="auth, auth-int",algorithm=MD5,nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'; break;
			#[RFC7486, Section 3]	The HOBA scheme can be used with either HTTP servers or proxies. When used in response to a 407 Proxy Authentication Required indication, the appropriate proxy authentication header fields are used instead, as with any other HTTP authentication scheme.
        case 'hoba': $text = 'HOBA'; break;
        	#[RFC8120]
        case 'mutual': $text = 'Mutual'; break;
        	#[RFC4559, Section 3]	This authentication scheme violates both HTTP semantics (being connection-oriented) and syntax (use of syntax incompatible with the WWW-Authenticate and Authorization header field syntax).
        case 'negotiate': $text = 'Negotiate'; break;
        	#[RFC5849, Section 3.5.1]
        case 'oauth': $text = 'OAuth'; break;
        	#[RFC7804]
        case 'SCRAM-SHA-1': $text = 'SCRAM-SHA-1'; break;
        	#[RFC7804]
        case 'SCRAM-SHA-256': $text = 'SCRAM-SHA-256'; break;
        default:
            return NULL;
        break;
    }
    return $text;
}

function doPingback($RHOST, $LHOST){ 

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL,$RHOST);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 0);
curl_setopt($ch, CURLOPT_HEADER, 1);
#proxy options
#$proxy = 'http://127.0.0.1:8080';
#curl_setopt($ch, CURLOPT_PROXY, $proxy);
#curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxyauth);   //#Platform auth
#curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5); // If expected to call with specific PROXY type
#curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);  // If url has redirects then go to the final redirected URL.

$headers = [
        'Cache-Control' => 'no-transform',
        'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 ' . $RHOST,
        'Referer' => 'http://' . $LHOST . '/ref',
        'True-Client-IP' => $LHOST,
        'X-Client-IP' => $LHOST,
        'X-Forwarded-For' => $LHOST,
        'From' => 'root@'.$LHOST,
        'Client-IP' => $LHOST,
        'X-Real-IP' => $LHOST,
        'Forwarded' => 'for='.$LHOST.';by='.$LHOST.';host='.$LHOST,
        'Contact' => 'root@'.$LHOST,
        'X-Wap-Profile' => 'http://'.$LHOST.'/wap.xml',
        'X-Originating-IP' => $LHOST
];

curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

$server_output = curl_exec ($ch);

curl_close ($ch);

print  $server_output;
}

function doShow($RHOST){ 
    $headers = array(
        'Cache-Control' => 'no-transform',
        'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 ' . $RHOST,
        'Referer' => 'http://' . $RHOST . '/ref',
        'True-Client-IP' => $RHOST,
        'X-Client-IP' => $RHOST,
        'X-Forwarded-For' => $RHOST,
        'From' => 'root@'.$RHOST,
        'Client-IP' => $RHOST,
        'X-Real-IP' => $RHOST,
        'Forwarded' => 'for='.$RHOST.';by='.$RHOST.';host='.$RHOST,
        'Contact' => 'root@'.$RHOST,
        'X-Wap-Profile' => 'http://'.$RHOST.'/wap.xml',
        'X-Originating-IP' => $RHOST
        );
    foreach ($headers as $headerType => $headerValue)
    {
       header($headerType . ': ' . $headerValue);
    }
}
function doRedirect($RHOST){
    if (!(hasParam('code'))){ 
        setParam('code','301');
    }
    header('Location: ' . urldecode($RHOST));
}
function doAuth($type){
    $authHeader = getAuthHeaderFromAuthType($type);
    if ($authHeader !== NULL){
        header($authHeader);
        if (!(hasParam('code'))){ 
            setParam('code','401');
        }
    }else{
        cleanupThenDie('unknown \'auth\' method');
    }
}
function doHeaders($headers){
if (is_array($headers)){
        $arbitraryHeaders = $headers;
        foreach ($arbitraryHeaders as &$arbitraryHeader) {
            if (strpos($arbitraryHeader, ':') > 0) {
                header(urldecode($arbitraryHeader));
            }
            else{
                header(urldecode($arbitraryHeader.':'));
            }
        }
    }
}


######################## BEGIN DOING THINGS 

#header_remove() is only comatible with PHP >=5.3
if (function_exists('header_remove')){
	header_remove('x-powered-by');
}
else{
	header('x-powered-by:');
}

#Add Pingback?
if (hasParam('pingback')){
    if (hasParam('LHOST')){
        doPingback(getParam('RHOST'), getParam('pingback'));
    }
}

#Add Redirect?
if (hasParam('redirect')){
    doRedirect(getParam('redirect'));
}
#Add Authentication?
if (hasParam('auth')){
	doAuth(getParam('auth'));
}
#Add Headers?
if (hasParam('headers')){
    doHeaders(getParam('headers'));
}
#Add Body?
if (hasParam('body')){
    echo urldecode(getParam('body'));
}

#Force Protocol?
	$p = hasParam('protocol') ? urldecode(getParam('protocol')) : NULL;
	$c = hasParam('code') ? urldecode(getParam('code')) : NULL;
	$t = hasParam('text') ? urldecode(getParam('text')) : NULL;

if (($p) || ($c) || ($t)){
	header(advanced_http_response_code($p,$c,$t));
}


if (empty($_REQUEST)){
	?>
	<title>Respondent</title>
	<head></head>
	<body>

	<style>
body {
    font-family: "Lato", sans-serif;
}

.sidenav {
    height: 100%;
    width: 0;
    position: fixed;
    z-index: 1;
    top: 0;
    left: 0;
    background-color: #111;
    overflow-x: hidden;
    transition: 0.5s;
    padding-top: 60px;
}

.sidenav a {
    padding: 8px 8px 8px 32px;
    text-decoration: none;
    font-size: 25px;
    color: #818181;
    display: block;
    transition: 0.3s;
}

.sidenav a:hover {
    color: #f1f1f1;
}

.sidenav .closebtn {
    position: absolute;
    top: 0;
    right: 25px;
    font-size: 36px;
    margin-left: 50px;
}

#main {
    transition: margin-left .5s;
    padding: 16px;
}

@media screen and (max-height: 450px) {
  .sidenav {padding-top: 15px;}
  .sidenav a {font-size: 18px;}
}
</style>
</head>
<body>

<div id="mySidenav" class="sidenav">
  <a href="javascript:void(0)" class="closebtn" onclick="closeNav()">⚔️</a>
  <a href="#payloadgen">Payload Generator</a>
  <a href="#api">API Reference</a>
  <a href="#setup">Setup & Configuration</a>
</div>

<div id="main">
	<span style="font-size:30px;color:red;cursor:pointer" onclick="openNav()">&#9776; Menu</span> <h1>Respondent</h1>
	Respondent offers a way to quickly solicit a reflected, random, or custom response to a request, using a really simple syntax.<br>
	The main purpose for Respondent's existence is to aid in the security testing of components which process HTTP responses, where either:<br>
	<ul>
		<li>we know the response we want to make, but getting it requires configuring a server/proxying/effort. or;</li>
		<li>their logic/source-code is unknown and we want a way to fuzz responses using requests</li>		
	<ul>
	<p>
	A few examples might be:<br>
	
	<li><b>XSS testing</b><br>
			e.g. <a href="?headers[]=X-XSS-Protection:0&body=&lt;script&gt;alert()&lt;/script&gt;" target="_blank">?headers[]=X-XSS-Protection:0&body=&lt;script&gt;alert()&lt;/script&gt;</a></li>
	<li><b>401-Injection</b><br>
			Because you never have a Basic-Auth protected resource when you need one. <a href="?auth=basic" target="_blank">?auth=basic</a></li>
	<li><b>Client testing</b><br>
			Overflow in a protocol header? I've seen weirder. <a href="?protocol=HTTP/18446744073709551616" target="_blank">?protocol=HTTP/18446744073709551616</a></li></li>
	<li><b>SSRF Client testing</b><br>
			Why not test the client in a SSRF scenario? Most people will want to look at the internal hosts/services as soon as they get SSRF<br>
			...but what about fingerprinting the client, e.g. PHP/cURL,Python/requests, by seeing how it handles malformed responses<br> 
			and see if we can exploit that also? (How does it handle redirects to internal resourses? proxies? authentication-challenges?)<br>
			Let's not waste time changing server config or modifying files.	
	</ul>
	
	<hr>
	<!-------------------------------------------------------------------------------------------------------------------------------->

<h2 style="color:red" id="payloadgen">Payload Generator</h2>

Payload = <mark><a id="payload" href="?">?</a></mark><br>

Protocol:
<select name="protocol" id="protocol" onChange="buildPayload();">
	<option value="">Same as Request (default)</option>
	<option value="1.1">HTTP/1.1</option>
	<option value="1.0">HTTP/1.0</option>
</select>

Status:
<select name="status" id="status" onChange="buildPayload();">
     <option value="">200 OK (default)</option>
     <option value="100 Continue">100 Continue</option>
    <option value="101 Switching Protocols">101 Switching Protocols</option>
    <option value="201 Created">201 Created</option>
    <option value="202 Accepted">202 Accepted</option>
    <option value="203 Non-Authoritative Information">203 Non-Authoritative Information</option>
    <option value="204 No Content">204 No Content</option>
    <option value="205 Reset Content">205 Reset Content</option>
    <option value="206 Partial Content">206 Partial Content</option>
    <option value="300 Multiple Choices">300 Multiple Choices</option>
    <option value="301 Moved Permanently">301 Moved Permanently</option>
    <option value="302 Moved Temporarily">302 Moved Temporarily</option>
    <option value="303 See Other">303 See Other</option>
    <option value="304 Not Modified">304 Not Modified</option>
    <option value="305 Use Proxy">305 Use Proxy</option>
    <option value="400 Bad Request">400 Bad Request</option>
    <option value="401 Unauthorized">401 Unauthorized</option>
    <option value="402 Payment Required">402 Payment Required</option>
    <option value="403 Forbidden">403 Forbidden</option>
    <option value="404 Not Found">404 Not Found</option>
    <option value="405 Method Not Allowed">405 Method Not Allowed</option>
    <option value="406 Not Acceptable">406 Not Acceptable</option>
    <option value="407 Proxy Authentication Required">407 Proxy Authentication Required</option>
    <option value="408 Request Time-out">408 Request Time-out</option>
    <option value="409 Conflict">409 Conflict</option>
    <option value="410 Gone">410 Gone</option>
    <option value="411 Length Required">411 Length Required</option>
    <option value="412 Precondition Failed">412 Precondition Failed</option>
    <option value="413 Request Entity Too Large">413 Request Entity Too Large</option>
    <option value="414 Request-URI Too Large">414 Request-URI Too Large</option>
    <option value="415 Unsupported Media Type">415 Unsupported Media Type</option>
    <option value="418 I'm A Teapot">418 I'm A Teapot</option>
    <option value="500 Internal Server Error">500 Internal Server Error</option>
    <option value="501 Not Implemented">501 Not Implemented</option>
    <option value="502 Bad Gateway">502 Bad Gateway</option>
    <option value="503 Service Unavailable">503 Service Unavailable</option>
    <option value="504 Gateway Time-out">504 Gateway Time-out</option>
    <option value="505 HTTP Version not supported">505 HTTP Version not supported</option>
</select>

Custom Status:<input type="text" name="rawstatus" id="rawstatus" placeholder="(000-999) (*)" onChange="buildPayload();"><br>

Content-Type:
<select name="type" id="type" onChange="buildPayload();">
	<option value="">text/html (default)</option>
    <option value="application/json">application/json</option>
    <option value="application/xml">application/xml</option>
    <option value="application/xhtml+xml">application/xhtml+xml</option>
    <option value="text/plain">text/plain</option>
    <option value="text/xml">text/xml</option>
    <option value="text/json">text/json</option>
    <option value="text/css">text/css</option>
    <option value="text/csv">text/csv</option>
    <option value="application/x-www-form-urlencoded">application/x-www-form-urlencoded</option>
    <option value="multipart/form-data">multipart/form-data</option>
</select>

Encoding:
<select name="charset" id="charset" onChange="buildPayload();">
     <option value="">UTF-8 (default)</option>
     <option value="ISO-8859-1">ISO-8859-1</option>
    <option value="UTF-16">UTF-16</option>
</select><br>

Body:<br>
<textarea rows="8" cols="100" name="body" id="body" onChange="buildPayload();"></textarea>

<p><b>Advanced</b><br>
Redirect:<input type="text" name="redirect" id="redirect" placeholder="//google.com" onChange="buildPayload();"><br>

Authorization:
<select name="status" id="status" onChange="buildPayload();">
    <option value="">None</option>
     <option value="basic">Basic</option>
     <option value="bearer">Bearer</option>
     <option value="digest">Digest</option>
</select><br>

 <div id="headerField">
    Custom headers:<a onclick='alert("If your PHP version is < 5.1.2 you can specify multiple headers in one \"headers\" paramerter by splitting them with \\n");'>💬</a><br>
    <input type="text" name="headers[]" id="headers" size="50" placeholder="header: value">
 </div>
 <input type="button" value="+" onClick="addField('headerField');">

<script>
    function addField(divName){
     
  var newdiv = document.createElement('div');
  newdiv.innerHTML = "<input type='text' name='headers[]' id='headers' size='50'>";
  document.getElementById(divName).appendChild(newdiv);

}
</script>

<strike><p><b>Raw Response</b><br>
Raw:<br>
<textarea rows="12" cols="100" name="raw" id="raw" placeholder="
HEAD http://example.com HTTP/1.1
Host: example.com:80
Connection: close
Access-Control-Request-Method: GET
User-Agent: Responder
Accept: */*
DNT: 1
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en;q=0.8
"onChange="buildPayload();"></textarea></strike>


<hr>
<!-------------------------------------------------------------------------------------------------------------------------------->


<h2 style="color:red" id="api">API Reference</h2>

	At least one parameter must be sent to Respondent to get a response, otherwise this page will display.<br>
	For flexibility all params can be sent via GET, POST or even as Cookies. Alternate HTTP methods (HEAD, PUT, DELETE, OPTIONS & CONNECT)<br>
	also work.<br>
	Note: Since you may want to have a parameter with the :/?#[]@!$&'()*+,;=] characters, or one with special unicode (CTLF/TRLO), these need URL-Encoding.<br>
	But that was pretty obvious.

	<h3>Main Header Control</h3>
	?<b>protocol</b> - Defines the protocol in the primary header response. Usually HTTP/1.0 or HTTP/1.1 (default = server deafult protocol).<br>
	?<b>code</b> - Defines the status code in the primary header response. Usually in range 000-999 (default = 200).<br>
	?<b>text</b> - Defines the status text in the primary header response. Arbitrary text (default = If ?<b>code</b> is present, uses the corresponding status text.<br>
	If no text is found or if ?<b>code</b> is unset, defaults to 'OK'.<br>

	<h3>Body Control</h3>
	?<b>body</b> - Defines the body of the response. 

	<h3>Redirects</h3>
	?<b>redirect</b> - Defines the location of a resource and builds a appropriate 'Location' header. If a 'redirect' value is given, the default status code<br>
	will become "301 Moved Permanently", this can be overriden with ?<b>code</b> and/or ?<b>text</b>. eg. ?redirect=//google.com&code=307.

	<h3>Authorization</h3>
	?<b>auth</b> - Defines an authentication challenge mode and builds the appropriate 'WWW-Authenticate' header. If an 'auth' value is given, the default status code<br>
	will become "401 Unauthorized", this can be overriden with ?<b>code</b> and/or ?<b>text</b>. eg. ?auth=basic&code=407.
	<p>Supported modes are currently; 'basic', 'bearer', or 'digest'.


	<strike><h3>Raw Response</h3>
	?<b>raw</b> - Defines a complete response to use.</strike>

<hr>

<!-------------------------------------------------------------------------------------------------------------------------------->

<h2 style="color:red" id="cheatsheet">Payload Cheatsheet</h2>

<table>
set-cookies: (storing dating within the agent)
content-location: (cacheing false links)
Upgrade: (try and force other protocol use i.e. IRC)
WWW-Authenticate: (try and force agent to authenticate)

</table>


<!-------------------------------------------------------------------------------------------------------------------------------->

<h2 style="color:red" id="setup">Setup, Quirks and Limitations (oh my!)</h2>

Server
<ul>
	<li>PHP is unable to remove additional webserver headers such as 'Server' or 'Date'. Therefore responses are not 100% customisable<br>
			unless you configure the webserver to remove these headers.</li>
</ul>
PHP
<ul>
	<li>PHP =>5.1.2 prevents more than one header from being sent at the same time to combat header injection attacks.<br>
		Therefore if you add '\n' into a header, the result is currently defined by your PHP version.</li>
</ul>
</div>

<script>
function openNav() {
    document.getElementById("mySidenav").style.width = "250px";
    document.getElementById("main").style.marginLeft = "250px";
}

function closeNav() {
    document.getElementById("mySidenav").style.width = "0";
    document.getElementById("main").style.marginLeft= "0";
}

function buildPayload(){
	url = '?';

	if (document.getElementById("protocol").value !== ""){
		url = url + 'protocol=HTTP/' + document.getElementById("protocol").value + '&';
	}
	if (document.getElementById("rawstatus").value !== ""){
		url = url + 'code=' + document.getElementById("rawstatus").value.split(" ", 1) + '&';
		url = url + 'text=' + encodeURIComponent(document.getElementById("rawstatus").value.substring(4)) + '&';
	}
	else{
        if (document.getElementById("status").value !== ""){
		  url = url + 'code=' + document.getElementById("status").value.split(" ", 1) + '&';
        }
	}
    if (document.getElementById("type").value !== ""){
        url = url + 'type=' + encodeURIComponent(document.getElementById("type").value) + '&';

    }
    if (document.getElementById("charset").value !== ""){
        url = url + 'charset=' + encodeURIComponent(document.getElementById("charset").value) + '&';

    }
	if (document.getElementById("body").value !== ""){
		url = url + 'body=' + encodeURIComponent(document.getElementById("body").value) + '&';

	}
    if (document.getElementById("headers").value !== ""){
        url = url + 'headers[]=' + encodeURIComponent(document.getElementById("headers").value) + '&';

    }
	
	document.getElementById("payload").innerHTML = url;
	document.getElementById("payload").href = url;
}
</script>

	</body>
	</html>
<?php
}
?>