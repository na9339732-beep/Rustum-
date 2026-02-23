<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

include __DIR__ . '/email_functions.php';

$result = sendEmail(
    "bsitfirsti@gmail.com",
    "Test Email",
    "<h2>Hello from EMIS!</h2><p>This is a test email.</p>"
);

echo $result ? "Sent!" : "Failed!";

