<?php 
    /*
    Plugin Name: Extended OTP Plugin
    Plugin URI: Plugin web site
    Description: OTP Plugin for WP
    Author: http://www.appsila.com
    Version: 1.0.0
	Author URI: http://www.appsila.com
	
	It is designed to be used in the login phase of the biosecure code in wordpress. It currently has shortcomings. You can contact Aden Ziya
	Akkaya for improvements. ademakkaya5@gmail.com
    */

function appsilaGetOTP($username, $password) {
	//echo "entered bio";
    
	$options = get_option( 'appsila_api_settings');
	
	$appsila_enabled = $options['appsila_api_text_field_2'];
	$appsila_email = $options['appsila_api_text_field_4'];
	$appsila_apikey = $options['appsila_api_text_field_3'];
	$appsila_otp_label = $options['appsila_api_text_field_0'];
	
    $apikey = $options['appsila_api_text_field_3'];
	
	$userid = $username;
	$header=array('Content-Type'=>'application/json; charset=UTF-8','x-lang'=>'tr','x-timezone'=>'180');
    $data_string='{"email":"'  . $appsila_email . '","userid":"'  . $userid . '","type":"'  . $type . '","apikey":"'  . $apikey . '"}';
   
	
	$url='https://appsila.com/notify.php'; //The serverd address or IP to which the biosecure code to be sent will be written to its variable here.
    
    $response = wp_remote_post( $url, array(
                        'method' => 'POST',
    
                        'headers' => $header,
    
                        'body' => $data_string
                    )
                  );
  
    if ( is_wp_error( $response ) ) {
       $error_message = $response->get_error_message();
       echo "Something went wrong: $error_message -" . $response;
	   die();
    } else {
	   
	   $response_code = wp_remote_retrieve_response_code( $response );
	   
	   if ($response_code == "404") {
	       echo appsilaDisplayLicenceError($username, $password,"Your license has expired or your license api-key may be invalid. Therefore, the BioSecure plug-in cannot continue its function.",2,0);
		   die();
	   }
	   elseif ($response_code == "401") {
		   echo appsilaDisplayLicenceError($username, $password,"Verification cannot be performed because an error occurred in the BioSecure communication. Please contact support@appsila.com...",1,0);
	       die();
	   }  
	   elseif ($response_code == "402") {
		   
		   $result=$response["body"];
             
	       $decoded = json_decode( preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $result), true );
		   
		   //echo $decoded['OTP'];

		   echo appsilaDisplayLicenceError($username, $password,"Your wordpress admin requires 2nd factor authentication using appsila Mobile APP!!!<br><br>Please install appsila Mobile APP and add Wordpress Service by entering the following code. Afterall please refresh this page.",3,$decoded['OTP']);
	       die(); 
	   }
	   elseif ($response_code != "200") {
		   echo appsilaDisplayLicenceError($username, $password,"Verification cannot be performed because there is an error in your BioSecure settings. Please contact support@appsila.com...",1,0);
	       die();
	   }
	   
	   $result=$response["body"];
             
	   $decoded = json_decode( preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $result), true );
      
       if (!empty($decoded)) {

          return $decoded['OTP'];

       }
     
    }
  
}

if ( !function_exists('wp_authenticate') ) :
    /**
     * Checks a user's login information and logs them in if it checks out.
     *
     * @since 2.5.0
     *
     * @param string $username User's username
     * @param string $password User's password
     * @return WP_Error|WP_User WP_User object if login successful, otherwise WP_Error object.
     */
    function wp_authenticate($username, $password) {
	
	$options = get_option( 'appsila_api_settings');
	$appsila_enabled = $options['appsila_api_text_field_2'];
	$my_value = "ffffff";
	 
	if( isset($_POST['my_extra_field_name']) )
	    $my_value = $_POST['my_extra_field_name'];
	   $oncedencekildi = false; 
	    if(get_option('oncedencekildi')){
			 $oncedencekildi = get_option('oncedencekildi');
			 
		}
		else {
				add_option('oncedencekildi', false);
				//echo "I set the option for the first time" . get_option('oncedencekildi');
		}
    
       $username = sanitize_user($username);
       $password = trim($password);
       $user = apply_filters('authenticate', null, $username, $password);
       $cekilenotp = "00000";
	  
        if (!empty($username) && !empty($password)) 
        {
	   
       if ( empty($user->user_login) ) {
            // TODO what should the error message be? (Or would these even happen?)
            // Only needed if all authentication handlers fail to return anything.
          
			update_option('oncedencekildi', false);
            return new WP_Error('authentication_failed', __('<strong>HATA</strong>: 1-Girişte hata algılandı.'));
       
	   } elseif ($appsila_enabled != 1) {
		   update_option('oncedencekildi', false);
		   return $user;
	    
		} elseif ($my_value == get_option('sessionid')) {
		   update_option('oncedencekildi', false);
		   return $user;
	    
		} elseif (get_option('oncedencekildi') == false) {
            if (get_option('sessionid'))
			    delete_option('sessionid');
			
			$cekilenotp = appsilaGetOTP($username, $password); 
			
			
           
			if(get_option('cekilenotp') != "00000"){
				
				update_option('cekilenotp', $cekilenotp);
				
			}
			else {
				
				add_option('cekilenotp', $cekilenotp);
				
			}
			
			//echo " Your Code: " . get_option('cekilenotp');
			$oncedencekildi = true;
			update_option('oncedencekildi', true);
           
			echo appsilaGetHtml($username, $password, "");
			die();
        
        }
        $ignore_codes = array('empty_username', 'empty_password');
        if (is_wp_error($user) && !in_array($user->get_error_code(), $ignore_codes) ) {
            do_action('wp_login_failed', $username);
        }
        
		
		if(!$user || empty($password) || $my_value != get_option('cekilenotp')){
            
                
                remove_action('authenticate', 'wp_authenticate_username_password', 20);
                remove_action('authenticate', 'wp_authenticate_email_password', 20);
               
				
		    echo appsilaGetHtml($username, $password, "<strong>HATA</strong>:You have entered the verification code incorrectly. Please try again.");
			die();
			
        } 
		    update_option('oncedencekildi', false);
		     return $user;
		
       } 
        
		return $user;
	   
    }
    endif;

function appsilaDisplayLicenceError($user, $pass, $msg, $type, $registercode) {
	$html="";	
	
	$sessionid = mt_rand(100000, 999999);
		if(get_option('sessionid')){
				update_option('sessionid', $sessionid);
			}
			else {
				add_option('sessionid', $sessionid);
			}
	
	$html2_1 = '<head>
	<link rel=\'stylesheet\' href=\'wp-admin/load-styles.php?c=0&amp;dir=ltr&amp;load%5B%5D=dashicons,buttons,forms,l10n,login&amp;ver=4.9.11\' type=\'text/css\' media=\'all\' />
	</head>
	<body class="login login-action-login wp-core-ui  locale-en-us">
		<div id="login">
		<img width="200" src="http://appsila.com/wp-content/uploads/2018/10/appsila_v2_transparant.png" alt="light logo" style="margin-left: auto;margin-right: auto;display: block;">
		';
			
	$html2_2 = '<p class="message"> <center><b>	' . "123456" . '</b><br /></p>';
	
	$html2_3 = '<form name="loginform" id="loginform" action="wp-login.php" method="post">
<p class="message">	' . $msg . '<br /></p>
<p></p>
	<input type="hidden" name="my_extra_field_name" id="user_login" aria-describedby="login_error" class="input" value="' . $sessionid . '" size="20" /></label>
	<input type="hidden" name="log" value="' . $user . '">
	<input type="hidden" name="pwd" value="' . $pass . '">
	
	<p class="submit">
		<br />
		<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Continue without 2nd Factor" />
		<input type="hidden" name="redirect_to" value="http://appsila.com/wp-admin/" />
		<input type="hidden" name="testcookie" value="1" />
	</p>
</form></div></body>';

$html2_4 = '<form name="loginform" id="loginform" action="wp-login.php" method="post">
	<p class="message">	' . $msg . '<br /></p>
	<p></p>
	<input type="hidden" name="my_extra_field_name" id="user_login" aria-describedby="login_error" class="input" value="' . $sessionid . '" size="20" /></label>
	<input type="hidden" name="log" value="' . $user . '">
	<input type="hidden" name="pwd" value="' . $pass . '">
	
	<p class="submit">
		<br />
		<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Continue without 2nd Factor" />
		<input type="hidden" name="redirect_to" value="http://appsila.com/wp-admin/" />
		<input type="hidden" name="testcookie" value="1" />
	</p>
</form></div></body>';

$html2_5 = '<form name="loginform" id="loginform" action="wp-login.php" method="post">
	<p class="message">	' . $msg . '<br />
	</p>
	<p></p>
	<p><center><b>	<br /><br /><span style="color:red;"><font size="6">' . $registercode . '</font></span></b><br /></p>
	<input type="hidden" name="log" value="' . $user . '">
	<input type="hidden" name="pwd" value="' . $pass . '">
	
	<p class="submit">
		<br />
		<input type="hidden" name="redirect_to" value="http://appsila.com/wp-admin/" />
		<input type="hidden" name="testcookie" value="1" />
	</p>

</form></div></body>';
	
	
	if ($type == 1) {
	   $html = $html2_1 . $html2_3;
	} 
	elseif ($type == 3) {
	   $html = $html2_1 . $html2_5;
	} 
	else {
	   $html = $html2_1 . $html2_4;
	}
	
	return $html;
}


function appsilaGetHtml($user, $pass, $msg) {
	$options = get_option( 'appsila_api_settings');
	$appsila_otp_label = $options['appsila_api_text_field_0'];
	
	$html = " <html xmlns='http://www.w3.org/1999/xhtml'>
    <head>
       <script type='text/javascript'>
            function submit_by_name() {
			var x = document.getElementsByName('otpform');
           			   
            }
			
			 
			
        </script> 
    </head>
	<body>
	<div style='padding:250px;'>
	<center>
	<form method='post' name='otpform' action='wp-login.php'>
	<br>" . $msg . "<br>
	Please enter your OTP:
    <input type='text' name='my_extra_field_name'><br>
	<input type='hidden' name='log' value='" . $user . "'>
	<input type='hidden' name='pwd' value='" . $pass . "'>
	<input type='submit'>
	</form>
	</div>
	</body>
	</html>";
	
	$html2="";
	$html2_1 = '<head>
	<link rel=\'stylesheet\' href=\'wp-admin/load-styles.php?c=0&amp;dir=ltr&amp;load%5B%5D=dashicons,buttons,forms,l10n,login&amp;ver=4.9.11\' type=\'text/css\' media=\'all\' />
	</head>
	<body class="login login-action-login wp-core-ui  locale-en-us">
		<div id="login">
		<img width="200" src="http://appsila.com/wp-content/uploads/2018/10/appsila_v2_transparant.png" alt="light logo" style="margin-left: auto;margin-right: auto;display: block;">
		';
		
	$html2_2 = '<p class="message">	' . $msg . '<br /></p>';
	
$html2_3 = '<form name="loginform" id="loginform" action="wp-login.php" method="post">
	<p>
		<label for="user_login">' . $appsila_otp_label . '<br />
		<input type="text" name="my_extra_field_name" id="user_login" aria-describedby="login_error" class="input" value="" size="20" /></label>
	</p>
	<p>
	<input type="hidden" name="log" value="' . $user . '">
	<input type="hidden" name="pwd" value="' . $pass . '">

	<p class="submit">
		<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Submit" />
		<input type="hidden" name="redirect_to" value="http://appsila.com/wp-admin/" />
		<input type="hidden" name="testcookie" value="1" />
	</p>
</form></div></body>';
	
	if (empty($msg)) {
	   $html2 = $html2_1 . $html2_3;
	} else {
	   $html2 = $html2_1 . $html2_2 . $html2_3;
	}
	
	
	return $html2;
}

function appsila_redirect_post($url, array $data)
{
    ?>
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
       <script type="text/javascript">
            function closethisasap() {
                document.forms["redirectpost"].submit();
            }
        </script> 
    </head>
    <body onload="closethisasap();">
    <form name="redirectpost" method="post" action="<? echo $url; ?>">
        <?php
        if ( !is_null($data) ) {
            foreach ($data as $k => $v) {
                echo '<input type="hidden" name="' . $k . '" value="' . $v . '"> ';
            }
        }
        ?>
    </form>
    </body>
    </html>
    <?php
    exit;
}

add_action( 'admin_menu', 'appsila_api_add_admin_menu' );
add_action( 'admin_init', 'appsila_api_settings_init' );

function appsila_api_add_admin_menu(  ) {
     add_options_page( 'appsila', 'appsila', 'manage_options', 'settings-api-page', 'appsila_api_options_page' );
 }

 
 function appsila_api_settings_init(  ) {
     register_setting( 'appsilaPlugin', 'appsila_api_settings' );
     
	 add_settings_section(
         'appsila_api_appsilaPlugin_section',
         __( 'appsila Configuration', 'wordpress' ),
         'appsila_api_settings_section_callback',
         'appsilaPlugin'
     );

     add_settings_field(
         'appsila_api_text_field_0',
         __( 'Authentication Question:', 'wordpress' ),
         'appsila_api_text_field_0_render',
         'appsilaPlugin',
         'appsila_api_appsilaPlugin_section'
     );
	
	 add_settings_field(
        'appsila_api_text_field_2',
        __( 'Enable appsila Authentication:', 'wordpress' ),
        'appsila_print_checkbox',
        'appsilaPlugin',
        'appsila_api_appsilaPlugin_section'
    );
	
	 add_settings_field(
        'appsila_api_text_field_3',
        __( 'appsila API Key:', 'wordpress' ),
        'appsila_print_custom_field',
        'appsilaPlugin',
        'appsila_api_appsilaPlugin_section'
    );
	 
	 add_settings_field(
        'appsila_api_text_field_4',
        __( 'appsila Email:', 'wordpress' ),
        'appsila_print_custom_email',
        'appsilaPlugin',
        'appsila_api_appsilaPlugin_section'
    );
 }
 
 function appsila_api_text_field_0_render(  ) {
     $options = get_option( 'appsila_api_settings' );
     ?>
     <input style= "width:20em" type='text' name='appsila_api_settings[appsila_api_text_field_0]' value='<?php echo $options['appsila_api_text_field_0']; ?>'>

     <?php
 }

    ?>

 <?php
 function appsila_api_settings_section_callback(  ) {
     //echo __( 'appsila Settings Page', 'wordpress' );
 }
 
 function appsila_api_options_page(  ) {
     ?>
     <form action='options.php' method='post'> 
        
         <?php
         settings_fields( 'appsilaPlugin' );
         do_settings_sections( 'appsilaPlugin' );
         submit_button('Save Settings');
         ?>

     </form>
<?php 
}

function appsila_print_custom_field()
{
    $options = get_option( 'appsila_api_settings' );
    echo '<input style= "width:20em" type="text" name="appsila_api_settings[appsila_api_text_field_3]" value="' . $options['appsila_api_text_field_3'] . '" />';
}

function appsila_print_custom_email()
{
    $options = get_option( 'appsila_api_settings' );
    echo '<input style= "width:20em" type="text" name="appsila_api_settings[appsila_api_text_field_4]" value="' . $options['appsila_api_text_field_4'] . '" />';
}

function appsila_print_checkbox(){

    $options = get_option( 'appsila_api_settings' );
	echo $html = '<input type="checkbox" name="appsila_api_settings[appsila_api_text_field_2]" value="1"' . checked( 1,$options['appsila_api_text_field_2'], false ) . '/>';
}

?>