<?php
/**
 * @package     Joomla.Libraries
 * @subpackage  Version
 *
 * @copyright   Copyright (C) 2005 - 2014 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE
 */

defined('JPATH_PLATFORM') or die;

/**
 * Version information class for the Joomla CMS.
 *
 * @package     Joomla.Libraries
 * @subpackage  Version
 * @since       1.0
 */
final class JVersion
{
	/** @var  string  Product name. */
	public $PRODUCT = 'Joomla!';

	/** @var  string  Release version. */
	public $RELEASE = '3.3';

	/** @var  string  Maintenance version. */
	public $DEV_LEVEL = '4';

	/** @var  string  Development STATUS. */
	public $DEV_STATUS = 'Stable';
