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
	const TIME_WINDOW = PluginMoresecurityLimiter::TIME_WINDOW;

	/**
	 * Reserva atómica de un intento de login ANTES de autenticar (MS-06).
	 *
	 * Comprobar el permiso y contar el intento ocurren dentro de la misma
	 * sección crítica (bloqueo por login + IP): solicitudes simultáneas ya no
	 * pueden superar a la vez el presupuesto. Un login correcto libera el
	 * intento con clearLoginTry().
	 *
	 * @return string|null null si se admite; 'ip', 'account' o 'busy' si se rechaza
	 */
	public static function reserve(string $login, string $ip): ?string
	{
		$config            = PluginMoresecurityConfig::getInstance();
		$account_threshold = self::getAccountThreshold($config);
		$ip_max            = (int) $config->fields['ip_max_attempts'];
		$ip_threshold      = (int) $config->fields['ip_threshold'];

		$track_account = $account_threshold > 0 || $ip_threshold > 0;
		$track_ip      = $ip !== '' && ($ip_max > 0 || $ip_threshold > 0);
		if (!$track_account && !$track_ip) {
			return null; // ninguna protección activa: no se almacena nada (MS-08)
		}

		$keys = ['login:' . mb_strtolower($login)];
		if ($ip !== '') {
			$keys[] = 'ip:' . $ip;
		}

		[$locked, $result] = PluginMoresecurityLimiter::withLocks(
			$keys,
			fn() => self::reserveLocked($login, $ip, $config, $account_threshold, $track_account, $track_ip)
		);

		return $locked ? $result : 'busy';
	}

	private static function reserveLocked(
		string $login,
		string $ip,
		PluginMoresecurityConfig $config,
		int $account_threshold,
		bool $track_account,
		bool $track_ip
	): ?string {
		$ip_max = (int) $config->fields['ip_max_attempts'];

		if ($ip !== '' && $ip_max > 0 && PluginMoresecurityLoginip::isBlocked($ip)) {
			return 'ip';
		}
		if ($track_account) {
			if (PluginMoresecurityLimiter::isBlockedNow(self::getTable(), ['login' => $login])) {
				return 'account';
			}
			// Umbral alcanzado sin "blocked" (umbral subido/activado con
			// contadores acumulados): se reconcilia aquí en vez de dejar
			// pasar o rechazar sin caducidad.
			if ($account_threshold > 0 && self::reconcile($login, $account_threshold, $config)) {
				return 'account';
			}
		}

		$overflow = false;
		if ($track_ip) {
			$overflow = PluginMoresecurityLoginip::isOverflow($login, $ip);
			PluginMoresecurityLoginip::addTry(
				$overflow ? PluginMoresecurityLimiter::ANON_BUCKET : $login,
				$ip
			);
			if ($ip_max > 0) {
				PluginMoresecurityLoginip::applyIpBlock($ip);
			}
		}

		if ($track_account && !($overflow && !self::exists($login))) {
			self::addTry($login, $account_threshold, $config);
		}

		return null;
	}

	private static function exists(string $login): bool
	{
		global $DB;

		return count($DB->request(['FROM' => self::getTable(), 'WHERE' => ['login' => $login], 'LIMIT' => 1])) > 0;
	}

	/**
	 * Si el contador alcanzó el umbral pero no hay bloqueo vigente ni
	 * caducado (blocked IS NULL), fija ahora el bloqueo y devuelve true.
	 */
	private static function reconcile(string $login, int $threshold, PluginMoresecurityConfig $config): bool
	{
		global $DB;

		$res = $DB->doQuery(
			"SELECT `login_try`, `blocked`,
				(`last_try` IS NOT NULL AND `last_try` < (NOW() - INTERVAL " . (int) self::TIME_WINDOW . " SECOND)) AS stale
			 FROM " . DBmysql::quoteName(self::getTable()) . " WHERE `login` = " . DBmysql::quoteValue($login)
		);
		$row = $res ? $DB->fetchAssoc($res) : null;
		if (!$row || (int) $row['stale'] === 1 || $row['blocked'] !== null || (int) $row['login_try'] < $threshold) {
			return false;
		}

		$delay = PluginMoresecurityLimiter::backoffDelay(
			(int) $config->fields['time_blocked'],
			(int) $row['login_try'] - $threshold,
			(int) $config->fields['max_time_blocked']
		);
		self::setBlocked($login, $delay);

		return true;
	}

	private static function setBlocked(string $login, int $delay): void
	{
		global $DB;

		$DB->doQuery(
			"UPDATE " . DBmysql::quoteName(self::getTable()) . "
			 SET `blocked` = NOW() + INTERVAL " . (int) $delay . " SECOND
			 WHERE `login` = " . DBmysql::quoteValue($login)
		);
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
	 * Cuenta el intento (ya reservado) y fija el bloqueo si procede. Los dos
	 * controles son independientes (MS-09): el umbral de cuenta aplica
	 * backoff; el de IP distintas aplica una duración acotada y recuperable
	 * (MS-03), nunca una fecha centinela.
	 */
	private static function addTry(string $login, int $account_threshold, PluginMoresecurityConfig $config): void
	{
		global $DB;

		$table   = self::getTable();
		$login_q = DBmysql::quoteValue($login);
		$stale   = "`last_try` IS NOT NULL AND `last_try` < (NOW() - INTERVAL " . (int) self::TIME_WINDOW . " SECOND)";

		// Los operandos de ON DUPLICATE KEY UPDATE se evalúan de izquierda a
		// derecha: `last_try` va el último para que "stale" use el valor previo.
		$DB->doQuery(
			"INSERT INTO " . DBmysql::quoteName($table) . " (`login`, `login_try`, `last_try`)
			 VALUES ($login_q, 1, NOW())
			 ON DUPLICATE KEY UPDATE
				`login_try` = IF($stale, 1, `login_try` + 1),
				`blocked`   = IF($stale, NULL, `blocked`),
				`last_try`  = NOW()"
		) or die($DB->error());

		$res = $DB->doQuery("SELECT `login_try` FROM " . DBmysql::quoteName($table) . " WHERE `login` = $login_q");
		$row = $res ? $DB->fetchAssoc($res) : null;
		if (!$row) {
			return;
		}
		$try = (int) $row['login_try'];

		$delay = 0;
		if ($account_threshold > 0 && $try >= $account_threshold) {
			$delay = PluginMoresecurityLimiter::backoffDelay(
				(int) $config->fields['time_blocked'],
				$try - $account_threshold,
				(int) $config->fields['max_time_blocked']
			);
		}

		$ip_threshold = (int) $config->fields['ip_threshold'];
		if ($ip_threshold > 0 && PluginMoresecurityLoginip::countDistinctIpsForLogin($login) >= $ip_threshold) {
			$max_delay = (int) $config->fields['max_time_blocked'];
			$delay = max(
				$delay,
				$max_delay > 0
					? min($max_delay, PluginMoresecurityLimiter::HARD_CEILING)
					: PluginMoresecurityLimiter::DISTRIBUTED_DEFAULT
			);
		}

		if ($delay > 0) {
			self::setBlocked($login, $delay);
		}
	}

	/**
	 * Login correcto (o contraseña verificada pendiente de MFA): libera el
	 * intento reservado de esta cuenta y de la pareja (login, ip).
	 */
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
	 * Desbloqueo administrativo (MS-03): limpia el bloqueo y los contadores
	 * de la cuenta, incluidas las IP distintas que la bloquearon.
	 */
	public static function unblock(string $login): bool
	{
		global $DB;

		$DB->update(self::getTable(), [
			'login_try' => 0,
			'last_try'  => null,
			'blocked'   => null,
		], ['login' => $login]);
		PluginMoresecurityLoginip::clearTriesForLogin($login);

		return true;
	}

	/**
	 * Cuentas con bloqueo vigente, para el listado administrativo.
	 */
	public static function getBlocked(int $limit = 100): array
	{
		return PluginMoresecurityLimiter::fetchAll(
			"SELECT `login`, `login_try`, `blocked` FROM " . DBmysql::quoteName(self::getTable()) . "
			 WHERE `blocked` IS NOT NULL AND `blocked` > NOW() ORDER BY `blocked` DESC LIMIT " . (int) $limit
		);
	}

	/**
	 * Retención (MS-08): borra por lotes filas inactivas y sin bloqueo vigente.
	 */
	public static function purge(int $retention_days, int $batch = 1000, int $max_batches = 50): int
	{
		return PluginMoresecurityRetention::purgeTable(self::getTable(), $retention_days, $batch, $max_batches);
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
				KEY `blocked` (`blocked`),
				KEY `last_try` (`last_try`)
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

			// 2.2.2: índice para la retención y fin de los bloqueos a 2037
			$migration->addKey($table, 'last_try');
			$migration->migrationOneTable($table);
			PluginMoresecurityLimiter::capLegacyBlocks($table);
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
