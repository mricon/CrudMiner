<?php

	/**
	 * Function library read in upon startup
	 *
	 * $Id: lib.inc.php,v 1.123 2008/04/06 01:10:35 xzilla Exp $
	 */

	include_once('./libraries/decorator.inc.php');
	include_once('./lang/translations.php');

	// Set error reporting level to max
	error_reporting(E_ALL);
 
	// Application name
	$appName = 'phpPgAdmin';

	// Application version
	$appVersion = '5.0.2';
