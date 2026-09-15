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

class PluginMoresecurityConfig extends CommonDBTM
{
	private static $instance = null;
	public static $rightname = 'config';

	// Tope de seguridad para los campos de duración (segundos), muy por
	// debajo del límite de TIMESTAMP (2038), para que ninguna combinación
	// de config pueda producir un "blocked" que reviente en SQL (UC-06/UC-10).
	private const MAX_BLOCK_SECONDS = 31536000; // 1 año

	private const COUNT_FIELDS = ['number_attempts', 'ip_max_attempts', 'ip_threshold', 'attempts_reset'];
	private const TIME_FIELDS  = ['time_blocked', 'max_time_blocked', 'ip_time_blocked', 'ip_max_time_blocked', 'time_reset'];

	public function __construct()
	{
		global $DB;
		if ($DB->tableExists($this->getTable())) {
			$this->getFromDB(1);
		}
	}

	/**
	 * getTypeName
	 *
	 * @param  mixed $nb
	 * @return string
	 */
	public static function getTypeName($nb = 0): string
	{
		return "More Security";
	}

	public static function getIcon(): string
	{
		return 'ti ti-lock-cog';
	}

	/**
	 * getInstance
	 *
	 * @param  mixed $n
	 * @return mixed
	 */
	public static function getInstance($n = 1): mixed
	{
		if (!isset(self::$instance)) {
			self::$instance = new self();
			if (!self::$instance->getFromDB($n)) {
				self::$instance->getEmpty();
			}
		}

		return self::$instance;
	}

	/**
	 * getTabNameForItem
	 *
	 * @param  mixed $item
	 * @param  mixed $withtemplate
	 * @return string
	 */
	public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): string
	{
		if ($item->getType() == 'Config') {
			return self::createTabEntry(self::getTypeName(1));
		}

		return '';
	}

	/**
	 * displayTabContentForItem
	 *
	 * @param  mixed $item
	 * @param  mixed $tabnum
	 * @param  mixed $withtemplate
	 * @return bool
	 */
	public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
	{
		if ($item->getType() == 'Config') {
			self::showConfigForm();
		}

		return true;
	}

	/**
	 * showConfigForm
	 *
	 * @return bool
	 */
	public static function showConfigForm(): bool
	{
		$config = self::getInstance();

		$template = "@moresecurity/forms/config.form.html.twig";
		TemplateRenderer::getInstance()->display($template, [
			'item' => $config,
			'options' => [
				'full_width' => true,
			],
		]);

		return true;
	}

	/**
	 * prepareInputForUpdate
	 *
	 * @param  mixed $input
	 * @return array
	 */
	public function prepareInputForUpdate($input): array
	{
		if ((!isset($input["itemtypes"])) || (!is_array($input["itemtypes"]))) {
			$input["itemtypes"] = [];
		}
		$input["itemtypes"] = exportArrayToDB($input["itemtypes"]);

		// Validación de tipo/rango en servidor (UC-06): los min/max del
		// formulario son solo de UI, un POST directo los salta. Un valor
		// no numérico o un array conservan el valor previo en vez de
		// reventar en SQL.
		foreach (self::COUNT_FIELDS as $field) {
			if (array_key_exists($field, $input)) {
				$input[$field] = self::clampInput($input[$field], 0, 100, (int) $this->fields[$field]);
			}
		}
		foreach (self::TIME_FIELDS as $field) {
			if (array_key_exists($field, $input)) {
				$input[$field] = self::clampInput($input[$field], 0, self::MAX_BLOCK_SECONDS, (int) $this->fields[$field]);
			}
		}

		// El umbral de bloqueo de CUENTA (number_attempts) debe ser siempre
		// mayor que el umbral de bloqueo por IP (ip_max_attempts). En caso
		// contrario, un atacante desde una única IP podría bloquear una
		// cuenta para todas las IPs antes de que su propia IP quedara
		// bloqueada (DoS por bloqueo de cuenta). Ver login.class.php.
		$number_attempts = (int) ($input['number_attempts'] ?? $this->fields['number_attempts']);
		$ip_max_attempts = (int) ($input['ip_max_attempts'] ?? $this->fields['ip_max_attempts']);

		if ($number_attempts > 0 && $ip_max_attempts > 0 && $number_attempts <= $ip_max_attempts) {
			// Deja hueco para poder superar a ip_max_attempts sin salirse
			// del rango [0,100] de number_attempts (evita el off-by-one a 101).
			$adjusted_ip_max_attempts = min($ip_max_attempts, 99);
			$input['number_attempts'] = $adjusted_ip_max_attempts + 1;
			$input['ip_max_attempts'] = $adjusted_ip_max_attempts;
			Session::addMessageAfterRedirect(
				__('The account lockout threshold must be greater than the IP lockout threshold. It has been adjusted automatically.', 'moresecurity'),
				true,
				WARNING
			);
		}

		// Auditoría de cambios de umbrales de seguridad (UC-11), mismo
		// patrón que PluginTamConfig: registrar manualmente en el
		// historial del Config nativo (itemtype='Config', items_id=1),
		// sin depender de rawSearchOptions()/dohistory.
		foreach ($this->fields as $key => $old_value) {
			if (array_key_exists($key, $input) && $input[$key] != $old_value) {
				Log::history(1, 'Config', [1, $key . ' ' . $old_value, $input[$key]]);
			}
		}

		return $input;
	}

	/**
	 * Convierte a entero acotado a [$min,$max]; si el valor no es numérico
	 * o es un array, devuelve $fallback en vez de propagar basura a SQL.
	 */
	private static function clampInput($value, int $min, int $max, int $fallback): int
	{
		if (is_array($value) || !is_numeric($value)) {
			return $fallback;
		}

		return max($min, min($max, (int) $value));
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
		$config = new self();
		if (!$DB->tableExists($table)) {
			$migration->displayMessage("Installing $table");
			$query = "CREATE TABLE IF NOT EXISTS $table (
			`id` int {$default_key_sign} NOT NULL auto_increment,
			`number_attempts` int NOT NULL DEFAULT '0',
			`time_blocked` int NOT NULL DEFAULT '300',
			`max_time_blocked` int NOT NULL DEFAULT '86400',
			`attempts_reset` int NOT NULL DEFAULT '0',
			`time_reset` int NOT NULL DEFAULT '300',
			`ip_max_attempts` int NOT NULL DEFAULT '0',
			`ip_time_blocked` int NOT NULL DEFAULT '300',
			`ip_max_time_blocked` int NOT NULL DEFAULT '86400',
			`ip_threshold` int NOT NULL DEFAULT '0',
			`whitelisted_ips` text DEFAULT NULL,
			PRIMARY KEY (`id`)
			) ENGINE=InnoDB DEFAULT CHARSET={$default_charset}
			COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";

			$DB->doQuery($query);

			$config->add([
				'id' => 1,
			]);
		} else {
			$migration->addField($table, 'attempts_reset', 'integer');
			$migration->addField($table, 'time_reset', 'integer', ['value' => 300]);

			//2.1.0
			$migration->dropField($table, 'time_window');
			$migration->addField($table, 'ip_max_attempts', 'integer', ['value' => 0]);
			$migration->addField($table, 'ip_time_blocked', 'integer', ['value' => 300]);
			$migration->addField($table, 'ip_threshold', 'integer', ['value' => 0]);
			$migration->addField($table, 'whitelisted_ips', 'text');

			//2.2.0
			$migration->addField($table, 'max_time_blocked', 'integer', ['value' => 86400]);
			$migration->addField($table, 'ip_max_time_blocked', 'integer', ['value' => 86400]);
			$migration->migrationOneTable($table);
		}
	}

	public static function uninstall(Migration $migration): void
	{
		$migration->dropTable(self::getTable());
	}
}
