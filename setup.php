<?php
/*
 -------------------------------------------------------------------------
 More Security plugin for GLPI
 Copyright (C) 2026 by the TICGAL Team.
 https://www.tic.gal
 -------------------------------------------------------------------------
 LICENSE
 This file is part of the More Security plugin.
 More Security plugin is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.
 More Security plugin is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with More Security. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------
 @package   More Security
 @author    the TICGAL team
 @copyright Copyright (c) 2022-2026 TICGAL team
 @license   AGPL License 3.0 or (at your option) any later version
				http://www.gnu.org/licenses/agpl-3.0-standalone.html
 @link      https://www.tic.gal
 @since     2022
 ----------------------------------------------------------------------
*/

use Glpi\Plugin\Hooks;
use Glpi\Http\Firewall;

define('PLUGIN_MORESECURITY_VERSION', '2.2.2');
define('PLUGIN_MORESECURITY_MIN_GLPI', '11.0.0');
define('PLUGIN_MORESECURITY_MAX_GLPI', '12.0.0');

function plugin_version_moresecurity()
{
	return [
		'name' => 'More Security',
		'version' => PLUGIN_MORESECURITY_VERSION,
		'author' => '<a href="https://tic.gal">TICGAL</a>',
		'homepage' => 'https://tic.gal',
		'license' => 'GPLv3+',
		'requirements' => [
			'glpi' => [
				'min' => PLUGIN_MORESECURITY_MIN_GLPI,
				'max' => PLUGIN_MORESECURITY_MAX_GLPI,
			]
		]
	];
}

function plugin_init_moresecurity()
{
	global $PLUGIN_HOOKS;

	$PLUGIN_HOOKS['csrf_compliant']['moresecurity'] = true;

	Firewall::addPluginStrategyForLegacyScripts(
		'moresecurity',
		'#^/front/login\.form\.php$#',
		Firewall::STRATEGY_NO_CHECK
	);
	Firewall::addPluginStrategyForLegacyScripts(
		'moresecurity',
		'#^/front/lostpassword\.form\.php$#',
		Firewall::STRATEGY_NO_CHECK
	);

	$plugin = new Plugin();
	if ($plugin->isActivated('moresecurity')) {
		$PLUGIN_HOOKS['config_page']['moresecurity'] = 'front/config.form.php';
		Plugin::registerClass('PluginMoresecurityConfig', ['addtabon' => 'Config']);
		Plugin::registerClass('PluginMoresecurityWhitelist', ['addtabon' => 'Config']);

		$PLUGIN_HOOKS[Hooks::DISPLAY_LOGIN]['moresecurity'] = 'plugin_moresecurity_displayLogin';
		$PLUGIN_HOOKS[Hooks::POST_INIT]['moresecurity'] = 'plugin_moresecurity_enforce_login_gate';
	}
}
