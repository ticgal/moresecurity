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

namespace GlpiPlugin\Moresecurity;

use CommonDBTM;
use DBConnection;
use DBmysql;
use Glpi\Application\View\TemplateRenderer;
use Migration;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

class Lostpassword extends CommonDBTM
{
    /**
     * Reserva atómica de una solicitud de recuperación (MS-04/MS-06). Se
     * aplica la misma política a todas las rutas: presupuesto de la IP
     * (compartido con el login) y presupuesto de la dirección.
     *
     * @return string|null null si se admite; 'ip', 'email' o 'busy' si se rechaza
     */
    public static function reserve(string $email, string $ip): ?string
    {
        $config   = Config::getInstance();
        $reset    = (int) $config->fields['attempts_reset'];
        $track_ip = $ip !== '' && (int) $config->fields['ip_max_attempts'] > 0;
        if ($reset <= 0 && !$track_ip) {
            return null; // sin protección activa no se almacena nada (MS-08)
        }

        $keys = ['mail:' . $email];
        if ($ip !== '') {
            $keys[] = 'ip:' . $ip;
        }

        [$locked, $result] = Limiter::withLocks(
            $keys,
            function () use ($email, $ip, $config, $reset, $track_ip) {
                if ($track_ip && Loginip::isBlocked($ip)) {
                    return 'ip';
                }
                if ($reset > 0) {
                    if (Limiter::isBlockedNow(self::getTable(), ['email' => $email])) {
                        return 'email';
                    }
                    // MS-05: umbral alcanzado sin caducidad registrada.
                    if (self::reconcile($email, $reset, $config)) {
                        return 'email';
                    }
                }
                if ($track_ip) {
                    Loginip::addTry(Limiter::ANON_BUCKET, $ip);
                    Loginip::applyIpBlock($ip);
                }
                if ($reset > 0) {
                    self::addTry($email, $reset, $config);
                }

                return null;
            },
        );

        return $locked ? $result : 'busy';
    }

    private static function window(): string
    {
        return "`last_try` IS NOT NULL AND `last_try` < (NOW() - INTERVAL " . (int) Limiter::TIME_WINDOW . " SECOND)";
    }

    private static function setBlocked(string $email, Config $config): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->doQuery(
            "UPDATE " . DBmysql::quoteName(self::getTable()) . "
			 SET `blocked` = NOW() + INTERVAL " . max(1, min((int) $config->fields['time_reset'], Limiter::HARD_CEILING)) . " SECOND
			 WHERE `email` = " . DBmysql::quoteValue($email),
        );
    }

    /**
     * Si el contador alcanzó el umbral sin bloqueo (umbral bajado o activado
     * después de acumular solicitudes), fija ahora una caducidad.
     */
    private static function reconcile(string $email, int $threshold, Config $config): bool
    {
        $rows = Limiter::fetchAll(
            "SELECT `email_try`, `blocked`, (" . self::window() . ") AS stale
			 FROM " . DBmysql::quoteName(self::getTable()) . " WHERE `email` = " . DBmysql::quoteValue($email),
        );
        $row = $rows[0] ?? null;
        if (!$row || (int) $row['stale'] === 1 || $row['blocked'] !== null || (int) $row['email_try'] < $threshold) {
            return false;
        }
        self::setBlocked($email, $config);

        return true;
    }

    private static function addTry(string $email, int $threshold, Config $config): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $table   = self::getTable();
        $email_q = DBmysql::quoteValue($email);
        $stale   = self::window();

        $DB->doQuery(
            "INSERT INTO " . DBmysql::quoteName($table) . " (`email`, `email_try`, `last_try`)
			 VALUES ($email_q, 1, NOW())
			 ON DUPLICATE KEY UPDATE
				`email_try` = IF($stale, 1, `email_try` + 1),
				`blocked`   = IF($stale, NULL, `blocked`),
				`last_try`  = NOW()",
        );

        $rows = Limiter::fetchAll(
            "SELECT `email_try` FROM " . DBmysql::quoteName($table) . " WHERE `email` = $email_q",
        );
        if ((int) ($rows[0]['email_try'] ?? 0) >= $threshold) {
            self::setBlocked($email, $config);
        }
    }

    public static function unblock(string $email): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::getTable(), [
            'email_try' => 0,
            'last_try'  => null,
            'blocked'   => null,
        ], ['email' => $email]);

        return true;
    }

    public static function getBlocked(int $limit = 100): array
    {
        return Limiter::fetchAll(
            "SELECT `email`, `email_try`, `blocked` FROM " . DBmysql::quoteName(self::getTable()) . "
			 WHERE `blocked` IS NOT NULL AND `blocked` > NOW() ORDER BY `blocked` DESC LIMIT " . (int) $limit,
        );
    }

    public static function purge(int $retention_days, int $batch = 1000, int $max_batches = 50): int
    {
        return Retention::purgeTable(self::getTable(), $retention_days, $batch, $max_batches);
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
     * @param  Migration $migration
     * @return void
     */
    public static function install(Migration $migration): void
    {
        /** @var \DBmysql $DB */
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
			   `last_try` TIMESTAMP NULL DEFAULT NULL,
			   PRIMARY KEY (`id`),
			   UNIQUE KEY `email` (`email`),
			   KEY `blocked` (`blocked`),
			   KEY `last_try` (`last_try`)
			   ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset}
			   COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";
            $DB->doQuery($query);
        } else {
            // 2.2.2 (MS-05/MS-06): ventana de inactividad e índice único para
            // el upsert atómico. Hay que fusionar duplicados antes del UNIQUE.
            $migration->addField($table, 'last_try', 'timestamp');
            $migration->migrationOneTable($table);
            self::mergeDuplicateEmails($table);
            $migration->dropKey($table, 'email');
            $migration->migrationOneTable($table);
            $migration->addKey($table, 'email', 'email', 'UNIQUE');
            $migration->addKey($table, 'last_try');
            $migration->migrationOneTable($table);
            Limiter::capLegacyBlocks($table);
        }
    }

    private static function mergeDuplicateEmails(string $table): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $dups = Limiter::fetchAll(
            "SELECT `email` FROM " . DBmysql::quoteName($table) . "
			 WHERE `email` IS NOT NULL GROUP BY `email` HAVING COUNT(*) > 1",
        );
        foreach ($dups as $dup) {
            $rows = iterator_to_array($DB->request([
                'FROM'  => $table,
                'WHERE' => ['email' => $dup['email']],
                'ORDER' => ['id ASC'],
            ]), false);
            $keep      = array_shift($rows);
            $email_try = (int) $keep['email_try'];
            $last_try  = $keep['last_try'];
            $blocked   = $keep['blocked'];
            foreach ($rows as $extra) {
                $email_try += (int) $extra['email_try'];
                if ($extra['last_try'] !== null && ($last_try === null || $extra['last_try'] > $last_try)) {
                    $last_try = $extra['last_try'];
                }
                if ($extra['blocked'] !== null && ($blocked === null || $extra['blocked'] > $blocked)) {
                    $blocked = $extra['blocked'];
                }
                $DB->delete($table, ['id' => $extra['id']]);
            }
            $DB->update($table, [
                'email_try' => $email_try,
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
