<!DOCTYPE html>
<html>
<title>404 Not Found</title>
<body>
<?php 

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                    //
// This file implements an auto-blocking functionality when a malicious script attempts to scan your Apache server    //
// for weaknesses by trying one path after another and receiving 404 responses.                                       //
//                                                                                                                    //
// Usage:                                                                                                             //
// 1) Install/Enable PHP on your Apache server                                                                        //
// 2) Add this file to your site.                                                                                     //
//    a) Configure the variables below to your site                                                                   //
// 3) Direct Apache to server this file as a 404 response                                                             //
//    a) In "httpd.conf" add this line: ErrorDocument 404 "/example_path/apache_auto_blocker.php"                     //
// 4) Restart Apache and test by hitting a non-existent file on your site enough times to trigger the ban             //
//    a) You can undo the ban by removing the banned IP address from the newly created .htaccess file.                //
//    b) Note: No restart is required after adding or removing entries from .htaccess                                 //
//                                                                                                                    //
// The following format is for Apache 2.4 and up                                                                      //
// The format of the .htaccess file must be as follows                                                                //
//                                                                                                                    //
// <RequireAll>                                                                                                       //
//    Require all granted                                                                                             //
//    Require not ip 1.1.1.1                                                                                          //
//    Require not ip 2.2.2.2                                                                                          //
// </RequireAll>                                                                                                      //
//                                                                                                                    //
// The following variables must be configured for your site                                                           //
// START CONFIGURATION                                                                                                //
                                                                                                                      //
// kTrackerLogFilename is the file that will be used to track IP addresses                                            //
$kTrackerLogFilename = "auto_lock.log";                                                                               //
                                                                                                                      //
 // kBlockListFileName is the ".htaccess" file apache uses to restrict access.                                        //
// This script will add bad actor IP addresses to this file. This can be site wide or within specific subdirectories. //
$kBlockListFileName = "c:/my_web_root/public_html/.htaccess";                                                         //
                                                                                                                      //
// kNumSecondsToTrack is how long history is kept in kTrackerLogFilename.                                             //
// The longer this time period the slower an attacker would need to rate limit their attack.                          //
$kNumSecondsToTrack = 60;                                                                                             //
                                                                                                                      //
// kMaxHitsToBlockAddress configures how many 404 responses in the tracking period before triggering the auto block.  //
// If there are this many 404 requests in $kNumSecondsToTrack period, the auto blocking is triggered.                 //
$kMaxHitsToBlockAddress = 5;                                                                                          //
                                                                                                                      //
// END CONFIGURATION                                                                                                  //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


$request_uri = $_SERVER['REQUEST_URI'];
$remote_addr = $_SERVER['REMOTE_ADDR'];

// Body of the request
echo('<h1>Not Found!</h1><br><p>The requested URL '.$request_uri.' was not found on this server.</p><br>');


// Record structure of 404 requests
class MissingDocAccessRecord 
{
  public $mRequest_uri;		// The requested resource
  public $mRemote_addr;		// The IP address of the requestor
  public $mRequest_time;	// Timestamp of the request
  
  public function __construct($request_uri, $remote_addr, $request_time) 
  {
    $this->mRequest_uri = $request_uri;
    $this->mRemote_addr = $remote_addr;
    $this->mRequest_time = $request_time;
  }
 
}

// Array of the requests
class MissingDocRecordArray
{
	public $mRecordArray = array();
	
	// Function to remove records older than a configured number of seconds
	function ClearOldRecords($olderThanSeconds)
	{
		$time = time();
		
		$arraySize = count($this->mRecordArray);
		for ($index = 0; $index < $arraySize; $index++)
		{
			if ($time - $this->mRecordArray[$index]->mRequest_time > $olderThanSeconds)
			{
				unset($this->mRecordArray[$index]);
			}
		}
		
		$this->mRecordArray = array_values($this->mRecordArray);
	}
	
	function CountInstancesOfAddress($addressInQuestion)
	{
		$nCount = 0;
		$arraySize = count($this->mRecordArray);
		for ($index = 0; $index < $arraySize; $index++)
		{
			if ($this->mRecordArray[$index]->mRemote_addr == $addressInQuestion)
			{
				$nCount++;
			}
		}
		
		return $nCount;
	}
}


// Function for debugging purposes only
function OutputArray($array)
{
	 foreach ($array as $arrayElement)
	 {
	 		echo serialize($arrayElement)."<br>";
	 }
};

function AddIPToBlockList($blockListFileName, $ip)
{
	// Tags for the .htaccess file
	$kStartTag = "<RequireAll>\nRequire all granted\n";  
	$kEndTag   = "\n</RequireAll>";

	
	if (file_exists($blockListFileName))
	{
		$blockString = file_get_contents($blockListFileName);	
		
		$nLength = strlen($blockString);
		$nLengthToTrim = $nLength - strlen($kEndTag);
		$blockString = substr($blockString, 0, $nLengthToTrim);  // strip the trailing "\n</RequireAll>"
		//echo "Loaded File $blockListFileName<br>contents:<b>$blockString</b><br>";
	}
	else
	{
		$blockString = $kStartTag;
	}
	
	$blockString = $blockString."\nRequire not ip ".$ip.$kEndTag;
	
	file_put_contents($blockListFileName, $blockString);	
}

// Read any existing records or create a new one
if (file_exists($kTrackerLogFilename))
{
	//echo "Found File $kTrackerLogFilename<br>";
	$inputString = file_get_contents($kTrackerLogFilename);
	$missingDocArray = unserialize( $inputString );
	$missingDocArray->ClearOldRecords($kNumSecondsToTrack);
}
else
{
	//echo "No File $kTrackerLogFilename<br>";
	$missingDocArray = new MissingDocRecordArray();
}


// Debugging
//$arr = $_SERVER;
//$pr = implode('+', $arr);
//echo "<font face='Verdana' size='3'><b>Referrer of this page  = $pr </b><br>";
//echo "<font face='Verdana' size='3'><b>Request URI  = $request_uri </b><br>";
//echo "<font face='Verdana' size='3'><b>Remote ADDR  = $remote_addr </b><br>";
//echo "<font face='Verdana' size='3'><b>Request time  = $request_time </b><br>";

// add the new 404 request to the array
array_push($missingDocArray->mRecordArray, new MissingDocAccessRecord($request_uri, $remote_addr, time()));

// persist the array
file_put_contents($kTrackerLogFilename, serialize( $missingDocArray ));


// Debugging
//OutputArray($missingDocArray);
//echo "Address Appears in list <b>".$missingDocArray->CountInstancesOfAddress($remote_addr)."</b> times.<br>";

if ($missingDocArray->CountInstancesOfAddress($remote_addr) > $kMaxHitsToBlockAddress)
{
	AddIPToBlockList($kBlockListFileName, $remote_addr);
}

 ?> 
</body>
</html>

