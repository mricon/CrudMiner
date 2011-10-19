<?php
/**
 * Script file of JFUploader component
 */

class com_jfuploaderInstallerScript
{ 
    private $cur_version = '2.10.3'; 
     /**
	 * method to install the component
	 *
	 * @return void
	 */
	function install($parent) 
	{
	  $this->jfu_install();
	}
