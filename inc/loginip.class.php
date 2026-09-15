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

class PluginMoresecurityLoginip extends CommonDBTM
{
    const TIME_WINDOW = 43200; // 12 horas en segundos

    public static function checkIp(string $ip): bool
    {
        global $DB;

        $query = [
            'FROM'  => self::getTable(),
            'WHERE' => ['ip' => $ip],
        ];

        foreach ($DB->request($query) as $row) {
            if (!is_null($row['blocked'])) {
                if ($row['blocked'] > date('Y-m-d H:i:s')) {
                    return false;
                } else {
                    // El bloqueo ha expirado: se permite reintentar, pero NO
                    // se resetea ip_try/last_try, para que el backoff pueda
                    // seguir escalando en el siguiente fallo (mismo motivo
                    // que en PluginMoresecurityLogin::checkLogin).
                    self::clearIpBlockedFlag($ip);
                }
            }
        }

        return true;
    }

    /**
     * Limpia solo la pareja (login, ip) que acaba de autenticarse
     * correctamente. No toca la actividad de otras cuentas en la misma IP
     * (UC-04): compartir IP no debe borrar la señal de ataque contra otros.
     */
    public static function clearIpTryForLogin(string $login, string $ip): void
    {
        global $DB;

        $DB->update(self::getTable(), [
            'ip_try'   => 0,
            'last_try' => null,
            'blocked'  => null,
        ], ['login' => $login, 'ip' => $ip]);
    }

    /**
     * Desbloquea la IP SIN resetear ip_try/last_try. Se usa cuando un
     * bloqueo temporal ha expirado, para que el backoff exponencial pueda
     * seguir escalando en el siguiente fallo en vez de reiniciarse a 0.
     */
    public static function clearIpBlockedFlag(string $ip): void
    {
        global $DB;

        $DB->update(self::getTable(), [
            'blocked' => null,
        ], ['ip' => $ip]);
    }

    public static function addIpTry(string $login, string $ip): void
    {
        global $DB;

        $config = PluginMoresecurityConfig::getInstance();
        $table  = self::getTable();

        // INSERT ... ON DUPLICATE KEY UPDATE es atómico a nivel de fila
        // (se apoya en la UNIQUE KEY login_ip): el incremento y el reset
        // por inactividad ocurren en una sola sentencia, sin la carrera de
        // lectura-modificación-escritura que perdía incrementos y
        // duplicaba filas bajo concurrencia (UC-10).
        $login_q = DBmysql::quoteValue($login);
        $ip_q    = DBmysql::quoteValue($ip);
        $window  = (int) self::TIME_WINDOW;

        $query = "INSERT INTO " . DBmysql::quoteName($table) . " (`login`, `ip`, `ip_try`, `last_try`)
            VALUES ($login_q, $ip_q, 1, NOW())
            ON DUPLICATE KEY UPDATE
                ip_try = IF(last_try IS NOT NULL AND last_try < (NOW() - INTERVAL $window SECOND), 1, ip_try + 1),
                last_try = NOW()";

        $DB->doQuery($query) or die($DB->error());

        // Bloqueo por IP: cuenta el TOTAL de intentos desde esta IP,
        // sumando todas las parejas (login, ip) -> sin importar qué usuario se probó.
        if ($config->fields['ip_max_attempts'] > 0) {
            $total = self::sumTriesForIp($ip);
            if ($total >= $config->fields['ip_max_attempts']) {
                // Backoff incremental, igual que en el bloqueo de cuenta:
                // cada fallo consecutivo por encima del umbral dobla la
                // espera respecto a la anterior, con un tope configurable.
                $excess = min($total - $config->fields['ip_max_attempts'], 30); // cap para evitar overflow en 2**n
                $delay  = $config->fields['ip_time_blocked'] * (2 ** $excess);

                $max_delay = $config->fields['ip_max_time_blocked'] ?? 0;
                if ($max_delay > 0) {
                    $delay = min($delay, $max_delay);
                }

                // Mismo tope duro que en el lado de cuenta (UC-06): nunca
                // más allá del centinela, aunque ip_max_time_blocked=0.
                $safety_ceiling = strtotime('2037-12-31 23:59:59') - time();
                $delay = min($delay, $safety_ceiling);

                $blocked = date('Y-m-d H:i:s', strtotime("+" . $delay . " seconds"));
                // Bloquea TODAS las filas de esta IP: afecta a cualquier login desde esa IP
                $DB->update($table, ['blocked' => $blocked], ['ip' => $ip]);
            }
        }
    }

    /**
     * Suma los intentos (ip_try) de todas las parejas login+ip para una IP dada,
     * considerando solo intentos recientes (dentro de TIME_WINDOW).
     */
    private static function sumTriesForIp(string $ip): int
    {
        global $DB;

        $result = $DB->request([
            'SELECT' => ['ip_try'],
            'FROM'   => self::getTable(),
            'WHERE'  => [
                'ip'       => $ip,
                'last_try' => ['>', date('Y-m-d H:i:s', strtotime("-" . self::TIME_WINDOW . " seconds"))],
            ],
        ]);

        $total = 0;
        foreach ($result as $row) {
            $total += (int) $row['ip_try'];
        }

        return $total;
    }

    public static function countDistinctIpsForLogin(string $login): int
    {
        global $DB;

        $config = PluginMoresecurityConfig::getInstance();
        $where  = ['login' => $login];
        $where['last_try'] = [
            '>',
            date('Y-m-d H:i:s', strtotime("-" . self::TIME_WINDOW . " seconds")),
        ];

        $result = $DB->request([
            'SELECT'  => ['ip'],
            'FROM'    => self::getTable(),
            'WHERE'   => $where,
            'GROUPBY' => ['ip'],
        ]);

        return count(iterator_to_array($result));
    }

    public static function install(Migration $migration): void
    {
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
                UNIQUE KEY `login_ip` (`login`, `ip`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";

            $DB->doQuery($query) or die($DB->error());
        } else {
            $migration->addKey($table, ['login', 'ip'], 'login_ip', 'UNIQUE');
            $migration->migrationOneTable($table);
        }
    }

    public static function uninstall(Migration $migration): void
    {
        $migration->dropTable(self::getTable());
    }
}
