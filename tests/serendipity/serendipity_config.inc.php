include(S9Y_INCLUDE_PATH . 'include/compat.inc.php');
if (defined('USE_MEMSNAP')) {
    memSnap('Framework init');
}

// The version string
$serendipity['version']         = '1.5.5';

// Setting this to 'false' will enable debugging output. All alpa/beta/cvs snapshot versions will emit debug information by default. To increase the debug level (to enable Smarty debugging), set this flag to 'debug'.
$serendipity['production']      = (preg_match('@\-(alpha|beta|cvs)@', $serendipity['version']) ? false : true);
