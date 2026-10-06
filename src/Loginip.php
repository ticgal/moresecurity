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
use Migration;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

class Loginip extends CommonDBTM
{
    public const TIME_WINDOW = Limiter::TIME_WINDOW;

    public static function isBlocked(string $ip): bool
    {
        return Limiter::isBlockedNow(self::getTable(), ['ip' => $ip]);
    }

    /**
     * ¿Esta IP ya ha usado demasiadas identidades distintas en la ventana?
     * Si es así, las identidades nuevas no crean filas (MS-08) y comparten
     * el cubo anónimo, que sigue sumando al presupuesto de la IP.
     */
    public static function isOverflow(string $login, string $ip): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $ip_q = DBmysql::quoteValue($ip);
        $res  = $DB->doQuery(
            "SELECT COUNT(*) AS c, SUM(`login` = " . DBmysql::quoteValue($login) . ") AS e
             FROM " . DBmysql::quoteName(self::getTable()) . "
             WHERE `ip` = $ip_q AND `last_try` > (NOW() - INTERVAL " . (int) self::TIME_WINDOW . " SECOND)",
        );
        $row = $DB->fetchAssoc($res);

        return $row
            && (int) $row['e'] === 0
            && (int) $row['c'] >= Limiter::MAX_IDENTITIES_PER_IP;
    }

    /**
     * Limpia solo la pareja (login, ip) que acaba de autenticarse
     * correctamente. No toca la actividad de otras cuentas en la misma IP
     * (UC-04): compartir IP no debe borrar la señal de ataque contra otros.
     */
    public static function clearIpTryForLogin(string $login, string $ip): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::getTable(), [
            'ip_try'   => 0,
            'last_try' => null,
            'blocked'  => null,
        ], ['login' => $login, 'ip' => $ip]);
    }

    /**
     * Reinicia los contadores de IP distintas de una cuenta (desbloqueo
     * administrativo). No levanta el bloqueo de la IP en sí.
     */
    public static function clearTriesForLogin(string $login): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::getTable(), [
            'ip_try'   => 0,
            'last_try' => null,
        ], ['login' => $login]);
    }

    /**
     * Desbloqueo administrativo de una IP: limpia bloqueo y contadores de
     * todas sus filas.
     */
    public static function unblock(string $ip): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::getTable(), [
            'ip_try'   => 0,
            'last_try' => null,
            'blocked'  => null,
        ], ['ip' => $ip]);

        return true;
    }

    public static function getBlocked(int $limit = 100): array
    {
        return Limiter::fetchAll(
            "SELECT `ip`, MAX(`blocked`) AS blocked FROM " . DBmysql::quoteName(self::getTable()) . "
             WHERE `blocked` IS NOT NULL AND `blocked` > NOW() GROUP BY `ip` ORDER BY blocked DESC LIMIT " . (int) $limit,
        );
    }

    /**
     * Cuenta el intento (ya reservado) de la pareja login+ip. El incremento
     * y el reinicio por inactividad ocurren en una sola sentencia atómica
     * (UNIQUE KEY login_ip).
     */
    public static function addTry(string $login, string $ip): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $table   = self::getTable();
        $stale   = "`last_try` IS NOT NULL AND `last_try` < (NOW() - INTERVAL " . (int) self::TIME_WINDOW . " SECOND)";

        // `last_try` va el último: los operandos se evalúan de izquierda a derecha.
        $DB->doQuery(
            "INSERT INTO " . DBmysql::quoteName($table) . " (`login`, `ip`, `ip_try`, `last_try`)
             VALUES (" . DBmysql::quoteValue($login) . ", " . DBmysql::quoteValue($ip) . ", 1, NOW())
             ON DUPLICATE KEY UPDATE
                `ip_try`   = IF($stale, 1, `ip_try` + 1),
                `blocked`  = IF($stale, NULL, `blocked`),
                `last_try` = NOW()",
        );
    }

    /**
     * Bloqueo por IP: suma (en SQL) los intentos de todas las parejas
     * login+ip de la ventana, sea cual sea la cuenta probada, y bloquea
     * todas las filas de la IP con backoff si se alcanza el umbral.
     */
    public static function applyIpBlock(string $ip): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $config = Config::getInstance();
        $max    = (int) $config->fields['ip_max_attempts'];
        if ($max <= 0) {
            return;
        }

        $total = self::sumTriesForIp($ip);
        if ($total < $max) {
            return;
        }

        $delay = Limiter::backoffDelay(
            (int) $config->fields['ip_time_blocked'],
            $total - $max,
            (int) ($config->fields['ip_max_time_blocked'] ?? 0),
        );

        $DB->doQuery(
            "UPDATE " . DBmysql::quoteName(self::getTable()) . "
             SET `blocked` = NOW() + INTERVAL " . (int) $delay . " SECOND
             WHERE `ip` = " . DBmysql::quoteValue($ip),
        );
    }

    private static function sumTriesForIp(string $ip): int
    {
        $rows = Limiter::fetchAll(
            "SELECT COALESCE(SUM(`ip_try`), 0) AS total FROM " . DBmysql::quoteName(self::getTable()) . "
             WHERE `ip` = " . DBmysql::quoteValue($ip) . "
               AND `last_try` > (NOW() - INTERVAL " . (int) self::TIME_WINDOW . " SECOND)",
        );

        return (int) ($rows[0]['total'] ?? 0);
    }

    public static function countDistinctIpsForLogin(string $login): int
    {
        $rows = Limiter::fetchAll(
            "SELECT COUNT(DISTINCT `ip`) AS c FROM " . DBmysql::quoteName(self::getTable()) . "
             WHERE `login` = " . DBmysql::quoteValue($login) . "
               AND `last_try` > (NOW() - INTERVAL " . (int) self::TIME_WINDOW . " SECOND)",
        );

        return (int) ($rows[0]['c'] ?? 0);
    }

    public static function purge(int $retention_days, int $batch = 1000, int $max_batches = 50): int
    {
        return Retention::purgeTable(self::getTable(), $retention_days, $batch, $max_batches);
    }

    public static function install(Migration $migration): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $default_charset   = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign  = DBConnection::getDefaultPrimaryKeySignOption();

        $table = self::getTable();
        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");
            $query = "CREATE TABLE IF NOT EXISTS $table (
                `id` int {$default_key_sign} NOT NULL AUTO_INCREMENT,
                `login` varchar(255) DEFAULT NULL,
                `ip` varchar(45) DEFAULT NULL,
                `ip_try` int NOT NULL DEFAULT '0',
                `last_try` TIMESTAMP NULL DEFAULT NULL,
                `blocked` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `login` (`login`),
                KEY `ip` (`ip`),
                KEY `blocked` (`blocked`),
                KEY `last_try` (`last_try`),
                UNIQUE KEY `login_ip` (`login`, `ip`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";

            $DB->doQuery($query);
        } else {
            // El UNIQUE solo puede crearse si no hay parejas duplicadas.
            self::mergeDuplicates($table);
            $migration->addKey($table, ['login', 'ip'], 'login_ip', 'UNIQUE');
            $migration->addKey($table, 'last_try');
            $migration->migrationOneTable($table);
            Limiter::capLegacyBlocks($table);
        }
    }

    /**
     * Fusiona filas duplicadas (login, ip) antes de crear el índice único:
     * suma ip_try y conserva el last_try y el blocked más recientes.
     */
    private static function mergeDuplicates(string $table): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $dups = Limiter::fetchAll(
            "SELECT `login`, `ip` FROM " . DBmysql::quoteName($table) . "
             GROUP BY `login`, `ip` HAVING COUNT(*) > 1",
        );
        foreach ($dups as $dup) {
            $rows = iterator_to_array($DB->request([
                'FROM'  => $table,
                'WHERE' => ['login' => $dup['login'], 'ip' => $dup['ip']],
                'ORDER' => ['id ASC'],
            ]), false);
            $keep = array_shift($rows);
            $ip_try   = (int) $keep['ip_try'];
            $last_try = $keep['last_try'];
            $blocked  = $keep['blocked'];
            foreach ($rows as $extra) {
                $ip_try += (int) $extra['ip_try'];
                if ($extra['last_try'] !== null && ($last_try === null || $extra['last_try'] > $last_try)) {
                    $last_try = $extra['last_try'];
                }
                if ($extra['blocked'] !== null && ($blocked === null || $extra['blocked'] > $blocked)) {
                    $blocked = $extra['blocked'];
                }
                $DB->delete($table, ['id' => $extra['id']]);
            }
            $DB->update($table, [
                'ip_try'   => $ip_try,
                'last_try' => $last_try,
                'blocked'  => $blocked,
            ], ['id' => $keep['id']]);
        }
    }

    public static function uninstall(Migration $migration): void
    {
        $migration->dropTable(self::getTable());
    }
}
