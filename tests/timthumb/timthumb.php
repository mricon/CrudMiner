<?php
/**
 * TimThumb script created by Ben Gillbanks, originally created by Tim McDaniels and Darren Hoyt
 * http://code.google.com/p/timthumb/
 * 
 * GNU General Public License, version 2
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 * Examples and documentation available on the project homepage
 * http://www.binarymoon.co.uk/projects/timthumb/
 */

define ('CACHE_SIZE', 1000);				// number of files to store before clearing cache
define ('CACHE_CLEAR', 20);					// maximum number of files to delete on each cache clear
define ('CACHE_USE', TRUE);					// use the cache files? (mostly for testing)
define ('CACHE_MAX_AGE', 864000);			// time to cache in the browser
define ('VERSION', '1.30');					// version number (to force a cache refresh)
