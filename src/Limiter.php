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

use DBmysql;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

/**
 * Utilidades comunes del limitador: reloj único (SQL), exclusión mutua por
 * clave, backoff acotado y validación de entradas del solicitante.
 */
class Limiter
{
    // Ventana de inactividad tras la cual se reinician los contadores.
    public const TIME_WINDOW = 43200; // 12 horas

    // Tope duro de cualquier bloqueo (MS-03/MS-10): muy por debajo del límite
    // de TIMESTAMP (2038) y siempre recuperable por caducidad.
    public const HARD_CEILING = 31536000; // 1 año

    // Duración por defecto del bloqueo por distribución de IP (MS-03/MS-09)
    // cuando max_time_blocked no está definido.
    public const DISTRIBUTED_DEFAULT = 86400;

    // Cubo anónimo de loginip: intentos de recuperación y de identidades
    // excedentes. Cuenta para la suma de la IP pero no para IP distintas.
    public const ANON_BUCKET = '';

    // Identidades distintas por IP y ventana a partir de las cuales se deja
    // de crear filas nuevas (MS-08).
    public const MAX_IDENTITIES_PER_IP = 100;

    public const MAX_IDENTITY_LENGTH = 255;
    public const MAX_PASSWORD_LENGTH = 4096;

    /**
     * Devuelve la cadena si es un escalar string no vacío (tras trim) y cabe
     * en la columna; null en caso contrario (MS-11).
     */
    public static function cleanIdentity(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $value = trim($value);
        if ($value === '' || strlen($value) > self::MAX_IDENTITY_LENGTH || str_contains($value, "\0")) {
            return null;
        }

        return $value;
    }

    public static function cleanEmail(mixed $value): ?string
    {
        $email = self::cleanIdentity($value);
        if ($email === null || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }

        return mb_strtolower($email);
    }

    public static function isPlainString(mixed $value, int $max = self::MAX_PASSWORD_LENGTH): bool
    {
        return is_string($value) && strlen($value) <= $max && !str_contains($value, "\0");
    }

    /**
     * Backoff exponencial acotado: base * 2^excess, limitado por $cap (si > 0)
     * y por el tope duro. Nunca devuelve menos de 1 segundo (MS-10).
     */
    public static function backoffDelay(int $base, int $excess, int $cap = 0): int
    {
        $base  = max(1, $base);
        $delay = $base * (2 ** min(max($excess, 0), 30));
        if ($cap > 0) {
            $delay = min($delay, $cap);
        }

        return max(1, min($delay, self::HARD_CEILING));
    }

    /**
     * Ejecuta $callback con exclusión mutua sobre las claves dadas
     * (GET_LOCK, orden estable para evitar interbloqueos). Si no se obtienen
     * los bloqueos devuelve [false, null]: el llamador debe fallar cerrado.
     *
     * @return array{0: bool, 1: mixed}
     */
    public static function withLocks(array $keys, callable $callback, int $timeout = 5): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $names = [];
        foreach (array_unique($keys) as $key) {
            $names[] = 'moresecurity:' . hash('xxh128', $key);
        }
        sort($names);

        $acquired = [];
        try {
            foreach ($names as $name) {
                $res = $DB->doQuery("SELECT GET_LOCK(" . DBmysql::quoteValue($name) . ", " . (int) $timeout . ") AS l");
                $row = $DB->fetchAssoc($res);
                if (!$row || (int) $row['l'] !== 1) {
                    return [false, null];
                }
                $acquired[] = $name;
            }

            return [true, $callback()];
        } finally {
            foreach (array_reverse($acquired) as $name) {
                $DB->doQuery("SELECT RELEASE_LOCK(" . DBmysql::quoteValue($name) . ")");
            }
        }
    }

    public static function fetchAll(string $sql): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $rows = [];
        $res = $DB->doQuery($sql);
        while ($row = $DB->fetchAssoc($res)) {
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * Fila con la marca de "bloqueada ahora" calculada por la base de datos,
     * para no mezclar el reloj de PHP con el de SQL.
     */
    public static function isBlockedNow(string $table, array $where): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $conditions = [];
        foreach ($where as $field => $value) {
            $conditions[] = DBmysql::quoteName($field) . ' = ' . DBmysql::quoteValue($value);
        }
        $res = $DB->doQuery(
            "SELECT 1 FROM " . DBmysql::quoteName($table) . "
             WHERE " . implode(' AND ', $conditions) . " AND `blocked` IS NOT NULL AND `blocked` > NOW() LIMIT 1",
        );

        return $DB->numrows($res) > 0;
    }

    /**
     * Recorta a la caducidad máxima los bloqueos heredados (p. ej. 2037).
     */
    public static function capLegacyBlocks(string $table): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->doQuery(
            "UPDATE " . DBmysql::quoteName($table) . "
             SET `blocked` = NOW() + INTERVAL " . (int) self::DISTRIBUTED_DEFAULT . " SECOND
             WHERE `blocked` > NOW() + INTERVAL " . (int) self::HARD_CEILING . " SECOND",
        );
    }
}
