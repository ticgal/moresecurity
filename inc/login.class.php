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

if (!defined('GLPI_ROOT')) {
	die("Sorry. You can't access directly to this file");
}

class PluginMoresecurityLogin extends CommonDBTM
{
	const TIME_WINDOW = 43200; // 12 horas en segundos

	public static function checkLogin($login)
	{
		global $DB;

		$config = PluginMoresecurityConfig::getInstance();
		$query = [
			'FROM'  => self::getTable(),
			'WHERE' => ['login' => $login]
		];
		if ($row = $DB->request($query)->current()) {
			if (!is_null($row['blocked'])) {
				if ($row['blocked'] === '9999-12-31 23:59:59') {
					return false;
				}
				if ($row['blocked'] > date('Y-m-d H:i:s')) {
					return false;
				} else {
					// El bloqueo ha expirado: se permite reintentar, pero
					// NO se resetea el contador de fallos (login_try/last_try).
					// Si se reseteara aquí, el backoff exponencial nunca
					// escalaría, porque cada ciclo de bloqueo empezaría
					// siempre desde 0 (ver PluginMoresecurityLogin::addLoginTry).
					// El contador solo se resetea en login correcto
					// (clearLoginTry) o tras inactividad prolongada (TIME_WINDOW).
					self::clearBlockedFlag($login);
					return true;
				}
			}
			$account_threshold = self::getAccountThreshold($config);
			if ($account_threshold > 0 && $row['login_try'] >= $account_threshold) {
				// Umbral alcanzado pero sin "blocked" fijado: puede pasar si
				// el umbral se sube/activa con contadores ya acumulados.
				// Reconciliamos aquí en vez de rechazar sin caducidad (UC-03).
				$blocked = self::computeBlockedUntil($login, $row['login_try'], $account_threshold, $config);
				$DB->update(self::getTable(), ['blocked' => $blocked], ['login' => $login]);
				if ($blocked <= date('Y-m-d H:i:s')) {
					self::clearBlockedFlag($login);
					return true;
				}
				return false;
			}
			return true;
		} else {
			// Primer registro de este login: con la UNIQUE KEY sobre
			// `login` (UC-10), un INSERT simple puede chocar con otra
			// petición concurrente que se adelantó. "ON DUPLICATE KEY
			// UPDATE login=login" es un no-op atómico: nunca lanza
			// excepción por carrera.
			$table = self::getTable();
			$DB->doQuery(
				"INSERT INTO " . DBmysql::quoteName($table) . " (`login`) VALUES (" . DBmysql::quoteValue($login) . ")
				 ON DUPLICATE KEY UPDATE `login` = `login`"
			) or die($DB->error());
			return true;
		}
	}

	/**
	 * Umbral efectivo de bloqueo de cuenta: nunca debe ser menor o igual
	 * al de bloqueo por IP. Si lo fuera (por configuración incorrecta),
	 * un atacante desde una única IP podría bloquear la cuenta para
	 * TODAS las IPs antes de que su propia IP quedara bloqueada.
	 */
	private static function getAccountThreshold(PluginMoresecurityConfig $config): int
	{
		$account_threshold = (int) $config->fields['number_attempts'];
		if (
			$account_threshold > 0
			&& $config->fields['ip_max_attempts'] > 0
			&& $account_threshold <= $config->fields['ip_max_attempts']
		) {
			$account_threshold = $config->fields['ip_max_attempts'] + 1;
		}

		return $account_threshold;
	}

	/**
	 * Backoff incremental: cada fallo consecutivo por encima del umbral
	 * dobla la espera respecto al anterior, con un tope configurable.
	 * Usado tanto al contar un fallo nuevo (addLoginTry) como al reconciliar
	 * un estado ya por encima del umbral pero sin "blocked" fijado (UC-03).
	 */
	private static function computeBlockedUntil(string $login, int $try, int $account_threshold, PluginMoresecurityConfig $config): string
	{
		$excess = min($try - $account_threshold, 30); // cap para evitar overflow en 2**n
		$delay  = $config->fields['time_blocked'] * (2 ** $excess);

		$max_delay = $config->fields['max_time_blocked'] ?? 0;
		if ($max_delay > 0) {
			$delay = min($delay, $max_delay);
		}

		// Tope duro independiente de la config: si max_time_blocked=0 (sin
		// límite) y el backoff escala lo suficiente, el retraso podría
		// producir una fecha fuera del rango de TIMESTAMP y hacer que el
		// login reviente en cada intento (UC-06/UC-10). Se acota en
		// segundos, ANTES de formatear la fecha: un año de más de 4 dígitos
		// ("12234-...") no se puede reparsear con strtotime() después.
		$safety_ceiling = strtotime('2037-12-31 23:59:59') - time();
		$delay = min($delay, $safety_ceiling);

		$blocked = date('Y-m-d H:i:s', strtotime("+" . $delay . " seconds"));

		if ($config->fields['ip_threshold'] > 0) {
			$distinctIps = PluginMoresecurityLoginip::countDistinctIpsForLogin($login);
			if ($distinctIps >= $config->fields['ip_threshold']) {
				$blocked = '2037-12-31 23:59:59';
			}
		}

		return $blocked;
	}

	public static function clearLoginTry($login)
	{
		global $DB;

		$DB->update(self::getTable(), [
			'login_try' => 0,
			'last_try'  => null,
			'blocked'   => null
		], [
			'login' => $login
		]);

		$ip = $_SERVER['REMOTE_ADDR'] ?? '';
		if ($ip) {
			PluginMoresecurityLoginip::clearIpTryForLogin($login, $ip);
		}
	}

	/**
	 * Desbloquea el login SIN resetear login_try/last_try. Se usa cuando
	 * un bloqueo temporal ha expirado, para que el backoff pueda seguir
	 * escalando en el siguiente fallo en vez de reiniciarse a 0.
	 */
	public static function clearBlockedFlag($login): void
	{
		global $DB;

		$DB->update(self::getTable(), [
			'blocked' => null,
		], [
			'login' => $login
		]);
	}

	public static function addLoginTry($login)
	{
		global $DB;

		$config = PluginMoresecurityConfig::getInstance();
		$ip = $_SERVER['REMOTE_ADDR'] ?? '';

		if ($ip) {
			PluginMoresecurityLoginip::addIpTry($login, $ip);
		}

		$table   = self::getTable();
		$login_q = DBmysql::quoteValue($login);
		$window  = (int) self::TIME_WINDOW;

		// INSERT ... ON DUPLICATE KEY UPDATE es atómico a nivel de fila (se
		// apoya en la UNIQUE KEY añadida sobre `login`): evita la carrera de
		// lectura-modificación-escritura que perdía incrementos y duplicaba
		// filas bajo concurrencia (UC-10).
		$query = "INSERT INTO " . DBmysql::quoteName($table) . " (`login`, `login_try`, `last_try`)
			VALUES ($login_q, 1, NOW())
			ON DUPLICATE KEY UPDATE
				login_try = IF(last_try IS NOT NULL AND last_try < (NOW() - INTERVAL $window SECOND), 1, login_try + 1),
				last_try = NOW()";

		$DB->doQuery($query) or die($DB->error());

		$row = $DB->request(['FROM' => $table, 'WHERE' => ['login' => $login]])->current();
		if (!$row) {
			return;
		}

		$account_threshold = self::getAccountThreshold($config);
		$blocked = null;
		if ($account_threshold > 0 && $row['login_try'] >= $account_threshold) {
			$blocked = self::computeBlockedUntil($login, $row['login_try'], $account_threshold, $config);
		}

		$DB->update($table, ['blocked' => $blocked], ['login' => $login]);
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
				`id` int {$default_key_sign} NOT NULL AUTO_INCREMENT,
				`login` varchar(255) DEFAULT NULL,
				`login_try` int NOT NULL DEFAULT '0',
				`blocked` TIMESTAMP NULL DEFAULT NULL,
				`last_try` TIMESTAMP NULL DEFAULT NULL,
				PRIMARY KEY (`id`),
				UNIQUE KEY `login` (`login`),
				KEY `blocked` (`blocked`)
			) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";

			$DB->doQuery($query) or die($DB->error());
		} else {
			// 2.1.0
			$migration->addField($table, 'last_try', 'timestamp');
			$migration->migrationOneTable($table);

			// 2.2.1 (UC-10): la concurrencia sin control pudo dejar filas
			// duplicadas por login; hay que fusionarlas antes de poder
			// convertir la KEY en UNIQUE (necesaria para el upsert atómico).
			// addKey() no sustituye una KEY no-única existente con el mismo
			// nombre, hay que borrarla primero.
			self::mergeDuplicateLogins($table);
			$migration->dropKey($table, 'login');
			$migration->migrationOneTable($table);
			$migration->addKey($table, 'login', 'login', 'UNIQUE');
		}
	}

	/**
	 * Fusiona filas duplicadas por `login` (posibles por la antigua carrera
	 * de concurrencia, UC-10): suma login_try, conserva el last_try y el
	 * blocked más recientes, y borra las filas sobrantes.
	 */
	private static function mergeDuplicateLogins(string $table): void
	{
		global $DB;

		$result = $DB->doQuery(
			"SELECT `login` FROM " . DBmysql::quoteName($table) . "
			 WHERE `login` IS NOT NULL
			 GROUP BY `login`
			 HAVING COUNT(*) > 1"
		);
		if (!$result) {
			return;
		}

		while ($dup = $DB->fetchAssoc($result)) {
			$rows = iterator_to_array($DB->request([
				'FROM'  => $table,
				'WHERE' => ['login' => $dup['login']],
				'ORDER' => ['id ASC'],
			]));
			$keep = array_shift($rows);
			$login_try = (int) $keep['login_try'];
			$last_try  = $keep['last_try'];
			$blocked   = $keep['blocked'];

			foreach ($rows as $extra) {
				$login_try += (int) $extra['login_try'];
				if ($extra['last_try'] !== null && ($last_try === null || $extra['last_try'] > $last_try)) {
					$last_try = $extra['last_try'];
				}
				if ($extra['blocked'] !== null && ($blocked === null || $extra['blocked'] > $blocked)) {
					$blocked = $extra['blocked'];
				}
				$DB->delete($table, ['id' => $extra['id']]);
			}

			$DB->update($table, [
				'login_try' => $login_try,
				'last_try'  => $last_try,
				'blocked'   => $blocked,
			], ['id' => $keep['id']]);
		}
	}

	public static function uninstall(Migration $migration): void
	{
		$migration->dropTable(self::getTable());
	}
}
