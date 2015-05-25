<?php
/**
 * @file /protect.php
 * "Protect" a website from accidental access by spiders
 * 
 * To initialize, call once through a browser, e.g. at https://example.com/protect.php
 * Enter the password (hardwired as "secret!")
 * 
 * This initializes an SQlite database DocRoot/var/protect.sqlite and
 * writes some rewrite rules at the end of the existing DocRoot/.htaccess file.
 * For this, these two files must be writable.
 * 
 * In the future, a user accessing the site from an unknown IP address is redirected
 * to /protect.php and has to enter the password. Her IP address is added to the SQlite database
 * and added as allowed address into the .htaccess file.
 */   

global $config;
const SCRIPT_NAME = 'protect.php';

function protect() {
    global $config;

    /*
     * Validate IP address
     */
    if (!empty($_SERVER["HTTP_X_FORWARDED_FOR"])) {
        // behind proxy, e.g. Varnish
        $remote_ip = $_SERVER["HTTP_X_FORWARDED_FOR"];
    }
    else {
        $remote_ip = $_SERVER["REMOTE_ADDR"];
    }

    if (empty($config)) {
        $config = array();
    }
    $ini = @parse_ini_file(dirname(__FILE__) . '/protect.ini');
    if ($ini) {
        if (!$config) {
            $config = array_merge($ini, $config);
        }
        else {
            $config = $ini;
        }
    }
    // Set defaults
    $config += array(
        'self' => $_SERVER['PHP_SELF'],
        'root' => '/',
        'password' => 'secret!',
        'database' => '%docroot/var/protect.sqlite',
        'htaccess' => '%docroot/.htaccess',
    );
    $db_name = strtr($config['database'], array('%docroot' => $_SERVER['DOCUMENT_ROOT']));

    $db = new MyDB($db_name);
    
    if (!$db) {
        message('Unable to open database ' . $db_name);
    }

    // Check if database is properly initialized
    if (!$db->query("SELECT COUNT(*) FROM ip_addresses")) {
        // Create required table
        if (!$db->query('CREATE TABLE "ip_addresses" (created timestamp,tag text,"ip_address" text NOT NULL PRIMARY KEY UNIQUE)')) {
            message(sqlite_error_string(sqlite_last_error($db)));
        }
        
        // Initialize IP addresses
        foreach (array(
            '::1', '127.0.0.1', // localhost
            '1.2.3.4', // own address
            '5.6.7.8', // partner #1
        ) as $ip_address) {
            
            $db->query(strftime("INSERT INTO ip_addresses(ip_address,created) VALUES('{$ip_address}','%Y-%m-%d %H:%M:%S')"));
            syslog(LOG_NOTICE, "Initialized IP address {$ip_address}");           
        }
    }

    $count = $db->querySingle("SELECT COUNT(*) FROM ip_addresses WHERE ip_address = '" . $remote_ip . "'");
    
    if ($count > 0) {
        if (basename($_SERVER['SCRIPT_NAME']) != SCRIPT_NAME) {
            //D syslog(LOG_NOTICE, "Allowed IP address {$remote_ip}");
            return; // allowed IP address 
        }
    }
    else {
        // Woah, a stranger. Show them the maintenance page
        if (basename($_SERVER['SCRIPT_NAME']) != SCRIPT_NAME) {
            header('Location: /maintenance.html');
            exit;
        }
    }
    
    /*
     * GET case. Present form
     */
    session_start();

    if (empty($_POST['protect_password'])) {
        page('Bitte geben Sie das Kennwort ein<br><input name="protect_password" type="password"><br><input type="submit" value="Anmelden">');
    }
    else
    if ($_POST['protect_password'] != $config['password']) {
        syslog(LOG_NOTICE, "Wrong password. {$remote_ip} access denied");
        message('Falsches Kennwort');
    }

    /*
     * POST case. Manipulate SQlite database
     */

    // if not, add it
    if ($count == 0) {
        if (!$db->query(strftime("INSERT INTO ip_addresses(ip_address,created) VALUES('{$remote_ip}','%Y-%m-%d %H:%M:%S')"))) {
             message($db->lastErrorMsg());    
        }
        syslog(LOG_NOTICE, "Added {$remote_ip} as allowed IP address");
    }
    $db->close();

    // Done. Try to access site. If all went well, IP address is now permitted without password
    header('Location: ' . $config['root']);
    exit;
}

/**
 * Emit a HTML form with $content as form body
 */  
function page($content) {
 ?>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <style type="text/css">
    * {
      font-family: Arial, helvetica, sans-serif;
      font-size: 16px;
    }
    body {
      margin: 0;
      padding: 0;
      background: #EEE;
    }
    form {
      width: 300px;
      margin: 60px auto;
      padding: 40px;
      background: white;
      -webkit-border-radius: 10px;
      -moz-border-radius: 10px;
      border-radius: 10px;
    }
    input[type="text"] {
      width: 140px;
    }
    p.msg-error {
      color: red;
    }
    p.msg-success {
        color: green;
    }
    input[type=submit] {
        display: block;
        margin-top: 10px;
    }
    </style>
  </head>
  <body>
    <form method="POST">
      <?php 
      if (!empty($_SESSION['protect_msg'])) {
        echo "<p class=\"msg-{$_SESSION['protect_msg_status']}\">{$_SESSION['protect_msg']}</p>";
        unset($_SESSION['protect_msg']);
      }
      echo $content; 
      ?>
    </form>
  </body>
</html>
 <?php
  exit;
}

class MyDB extends SQLite3
{
    function __construct($db_name)
    {
        $this->open($db_name);
    }
}

/**
 * Write a message to the session, redirect to /protect.php and exit
 */
function message($msg, $success = FALSE) {
    global $config;
    $_SESSION['protect_msg'] = $msg;
    $_SESSION['protect_msg_status'] = $success ? 'success' : 'error';
    header('Location: ' . $config['self']);
    exit;
}

protect();
