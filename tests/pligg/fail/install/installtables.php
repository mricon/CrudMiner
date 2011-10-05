///////////////////////////////////////////////////////////////////////////

$sql = "INSERT INTO `" . table_misc_data . "` ( `name` , `data` ) VALUES ('pligg_version', '1.1.5');";
mysql_query( $sql, $conn );
