<?php
$g_hostname               = getenv('DB_HOST');
$g_db_type                = getenv('DB_TYPE') ?: 'mysqli';
$g_database_name          = getenv('DB_NAME');
$g_db_username            = getenv('DB_USER');
$g_db_password            = getenv('DB_PASS')
$g_default_timezone       = getenv('TIMEZONE') ?: 'America/Los_Angeles';
$g_crypto_master_salt     = getenv('MASTER_SALT') ?: 'testtesttest';
$g_validate_email	  = getenv('VALIDATE_EMAIL') ?: "OFF";
//disable captcha
$g_signup_use_captcha     = getenv('USE_CAPTCHA') ?: OFF;
//setup mail
$g_phpMailer_method		  = PHPMAILER_METHOD_SMTP;
$g_smtp_host			  = getenv('SMTP_HOST');
$g_smtp_username		  = getenv('SMTP_USER');
$g_smtp_password		  = getenv('SMTP_PASS');
$g_smtp_connection_mode   = getenv('SMTP_MODE') ?: 'tls';
$g_smtp_port              = getenv('SMTP_PORT') ?: 587;
$g_log_level = LOG_EMAIL | LOG_EMAIL_REIPIENT | LOG_FILTERING | LOG_AJAX | LOG_LDAP;
#$g_log_level = LOG_LDAP;
$g_login_method 	  	= getenv("LOGIN_METHOD") ?: MD5;
$g_ldap_server			= getenv("LDAP_SERVER");
$g_ldap_root_dn			= getenv("LDAP_ROOT_DN");
$g_ldap_organization 		= getenv("LDAP_ORG") ?: "";
$g_ldap_protocol_version	= getenv("LDAP_VERSION") ?: 3;
$g_ldap_network_timeout		= getenv("LDAP_TIMEOUT") ?: 0;
$g_ldap_follow_referrals	= getenv("LDAP_REFERRALS") ?: "OFF";
$g_ldap_bind_dn			= getenv("LDAP_BIND_DN");
$g_ldap_bind_passwd		= getenv("LDAP_BIND_PASS");
$g_ldap_uid_field		= getenv("LDAP_UID_FIELD") ?: "sAMAccountName";
$g_lda_realname_field		= getenv("LDAP_REALNAME_FIELD") ?: "cn";
$g_use_ldap_realname		= getenv("LDAP_USE_REALNAME") ?: "OFF";
$g_use_ldap_email		= getenv("LDAP_USE_EMAIL") ?: "ON";
#$g_ldap_simulation_file_path	= "file:/var/www/html";
