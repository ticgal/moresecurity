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

use Glpi\Application\View\TemplateRenderer;

if (!defined('GLPI_ROOT')) {
	die("Sorry. You can't access directly to this file");
}

class PluginMoresecurityLostpassword extends CommonDBTM
{
	public static function checkEmail($email)
	{
		global $DB;

		$config = PluginMoresecurityConfig::getInstance();
		$query = [
			'FROM' => self::getTable(),
			'WHERE' => [
				'email' => $email
			]
		];
		if ($row = $DB->request($query)->current()) {
			if (!is_null($row['blocked'])) {
				if ($row['blocked'] > date('Y-m-d H:i:s')) {
					return false;
				} else {
					self::clearEmailTry($email);
					return true;
				}
			}
			if ($config->fields['attempts_reset'] > 0 && $row['email_try'] >= $config->fields['attempts_reset']) {
				return false;
			}
			return true;
		} else {
			$DB->insert(self::getTable(), [
				'email' => $email,
			]);
			return true;
		}
	}

	public static function clearEmailTry($email)
	{
		global $DB;

		$DB->update(self::getTable(), [
			'email_try' => 0,
			'blocked' => null
		], [
			'email' => $email
		]);
	}

	public static function addEmailTry($email)
	{
		global $DB;

		$config = PluginMoresecurityConfig::getInstance();
		$query = [
			'FROM' => self::getTable(),
			'WHERE' => [
				'email' => $email
			]
		];
		if ($row = $DB->request($query)->current()) {
			$try = $row['email_try'] + 1;
			$blocked = null;
			if ($config->fields['attempts_reset'] > 0 && $try >= $config->fields['attempts_reset']) {
				$blocked = date('Y-m-d H:i:s', strtotime("+ " . $config->fields['time_reset'] . " seconds"));
			}
			$input = [
				'email_try' => $try,
				'blocked' => $blocked,
			];
			$DB->update(self::getTable(), $input, [
				'email' => $email
			]);
		} else {
			$DB->insert(self::getTable(), [
				'email' => $email,
				'email_try' => 1
			]);
		}
	}

	public static function showPasswordForgetRequestForm()
	{
		TemplateRenderer::getInstance()->display('@moresecurity/forms/password_form.html.twig', [
			'title' => __('Forgotten password?'),
		]);
	}

	/**
	 * install
	 *
	 * @param  mixed $migration
	 * @return void
	 */
	public static function install(Migration $migration): void
	{
		global $DB;

		$default_charset = DBConnection::getDefaultCharset();
		$default_collation = DBConnection::getDefaultCollation();
		$default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();

		$table = self::getTable();
		if (!$DB->tableExists($table)) {
			$migration->displayMessage("Installing $table");
			$query = "CREATE TABLE IF NOT EXISTS $table (
			   `id` int {$default_key_sign} NOT NULL auto_increment,
			   `email` varchar(255) DEFAULT NULL,
			   `email_try` int NOT NULL DEFAULT '0',
			   `blocked` TIMESTAMP NULL DEFAULT NULL,
			   PRIMARY KEY (`id`),
			   KEY `email` (`email`),
			   KEY `blocked` (`blocked`)
			   ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset}
			   COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";
			$DB->doQuery($query) or die($DB->error());
		}
	}

	public static function uninstall(Migration $migration): void
	{
		$migration->dropTable(self::getTable());
	}
}
