<?php
if (version_compare(phpversion(), "5.3.0", ">=")  == 1)
  error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
else
  error_reporting(E_ALL & ~E_NOTICE);
set_magic_quotes_runtime(0);
ini_set('magic_quotes_sybase', 0);

/*------------------------------*/
/*----------Vars----------------*/
	$aConf = array();
	$aConf['release'] = '01.08.11';
	$aConf['iVersion'] = '7.0';
	$aConf['iPatch'] = '6';
	$aConf['dolFile'] = '../inc/header.inc.php';
	$aConf['confDir'] = '../inc/';	
	$aConf['headerTempl'] = <<<EOS
<?
