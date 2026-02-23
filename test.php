<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
include 'email_functions.php';

if(sendEmail("bsitfirsti@gmailcom","Test Email","Hello from EMIS!")){
    echo "Sent!";
}else{
    echo "Failed!";
}
