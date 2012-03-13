<?php
/**
 * @package    Joomla.Site
 *
 * @copyright  Copyright (C) 2005 - 2011 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

defined('_JEXEC') or die;

/**
 * Version information class for the Joomla CMS.
 *
 * @package  Joomla.Site
 * @since    1.0
 */
final class JVersion
{
	/** @var  string  Product name. */
	public $PRODUCT = 'Joomla!';

	/** @var  string  Release version. */
	public $RELEASE = '1.7';

	/** @var  string  Maintenance version. */
	public $DEV_LEVEL = '4';

	/** @var  string  Development STATUS. */
	public $DEV_STATUS = 'Stable';
