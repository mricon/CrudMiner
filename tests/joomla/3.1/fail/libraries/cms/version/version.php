<?php
/**
 * @package     Joomla.Libraries
 * @subpackage  Version
 *
 * @copyright   Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE
 */

defined('_JEXEC') or die;

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
	public $RELEASE = '3.1';

	/** @var  string  Maintenance version. */
	public $DEV_LEVEL = '6';

	/** @var  string  Development STATUS. */
	public $DEV_STATUS = 'Stable';
