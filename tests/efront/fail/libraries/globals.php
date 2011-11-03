<?php
function setDefines() {
    /*Get the build number*/
    preg_match("/(\d+)/", '$LastChangedRevision: 11994 $', $matches);
    $build = 11994;
    defined("G_BUILD") OR define("G_BUILD", $build);
}
