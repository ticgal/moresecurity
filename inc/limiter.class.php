<?php

/**
 * -------------------------------------------------------------------------
 * More Security plugin for GLPI
 * Copyright (C) 2026 by the TICGAL Team.
 * https://www.tic.gal
 * -------------------------------------------------------------------------
 * LICENSE
 * This file is part of the More Security plugin.
 * More Security plugin is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * More Security plugin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with More Security. If not, see <http://www.gnu.org/licenses/>.
 * -------------------------------------------------------------------------
 * @author    the TICGAL team
 * @copyright Copyright (c) 2022-2026 TICGAL team
 * @license   AGPL License 3.0 or (at your option) any later version
 * @link      https://www.tic.gal
 * @package   More Security
 * @since     2022
 *            http://www.gnu.org/licenses/agpl-3.0-standalone.html
 * -------------------------------------------------------------------------
 */

use Glpi\DBAL\QueryExpression;
use Glpi\DBAL\QueryFunction;
use Safe\Exceptions\SafeExceptionInterface;

use function Safe\inet_ntop;
use function Safe\inet_pton;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

/**
 * Utilidades comunes del limitador: reloj único (SQL), exclusión mutua por
 * clave, backoff acotado y validación de entradas del solicitante.
 */
class PluginMoresecurityLimiter
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
     * IP del solicitante: solo se confía en X-Forwarded-For cuando el par
     * inmediato (REMOTE_ADDR) es un proxy inverso configurado por el
     * administrador. Devuelve siempre una IPv4/IPv6 bien formada o '' (nunca
     * un nombre de host ni basura que acabe en una columna `ip`).
     */
    public static function getClientIp(): string
    {
        $remote_addr = self::validIp((string) ($_SERVER['REMOTE_ADDR'] ?? ''));

        $config  = PluginMoresecurityConfig::getInstance();
        $proxies = array_map([self::class, 'canonicalIp'], self::parseList((string) ($config->fields['trusted_proxies'] ?? '')));
        $remote_addr = self::canonicalIp($remote_addr);
        if ($remote_addr === '' || $proxies === [] || !in_array($remote_addr, $proxies, true)) {
            return $remote_addr;
        }

        // La cadena la va ampliando cada proxy: se recorre de derecha a
        // izquierda hasta el primer salto que no sea un proxy de confianza.
        $chain = array_reverse(self::parseList((string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '')));
        foreach ($chain as $candidate) {
            // Un salto que no es una IP (p. ej. "ip:puerto") rompe la cadena
            // de confianza: lo anterior lo escribió el cliente.
            $candidate = self::canonicalIp($candidate);
            if ($candidate === '') {
                return $remote_addr;
            }
            if (!in_array($candidate, $proxies, true)) {
                return $candidate;
            }
        }

        return $remote_addr;
    }

    /**
     * Clave de los contadores para una IP: IPv4 tal cual; IPv6 reducida a su
     * prefijo /64 (un solo suscriptor controla el /64 entero, así que contar
     * por dirección completa permitiría rotar y saltarse los límites). Una
     * clave ya reducida o una cadena no-IP se devuelve sin cambios.
     */
    public static function bucketIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return $ip;
        }
        try {
            $packed = inet_pton($ip);
            // IPv4 mapeada (::ffff:a.b.c.d): se cuenta como la IPv4 que lleva.
            if (str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
                return inet_ntop(substr($packed, 12));
            }
            return inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . '/64';
        } catch (SafeExceptionInterface $e) {
            return $ip;
        }
    }

    /**
     * Forma canónica de una IP válida (IPv6 comprimida y en minúsculas) para
     * comparar direcciones escritas con distinta notación; '' si no es IP.
     */
    public static function canonicalIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return '';
        }

        return inet_ntop(inet_pton($ip));
    }

    /**
     * @return string $ip sin cambios si es una IPv4/IPv6 válida, '' si no.
     */
    public static function validIp(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '';
    }

    /**
     * Lista separada por comas -> array sin vacíos ni espacios.
     *
     * @return string[]
     */
    public static function parseList(string $value): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $value)), static fn($v) => $v !== ''));
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
        global $DB;

        $names = [];
        foreach (array_unique($keys) as $key) {
            $names[] = 'moresecurity:' . sha1($key);
        }
        sort($names);

        $acquired = [];
        try {
            foreach ($names as $name) {
                $res = $DB->doQuery("SELECT GET_LOCK(" . DBmysql::quoteValue($name) . ", " . (int) $timeout . ") AS l");
                $row = $res ? $DB->fetchAssoc($res) : null;
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

    /**
     * Inicio de la ventana de conteo (ahora - TIME_WINDOW), calculado en SQL
     * para no mezclar el reloj de PHP con el de la base de datos.
     */
    public static function windowStart(): QueryExpression
    {
        return QueryFunction::dateSub(QueryFunction::now(), self::TIME_WINDOW, 'SECOND');
    }

    /**
     * Instante "ahora + $seconds" calculado en SQL.
     */
    public static function fromNow(int $seconds): QueryExpression
    {
        return QueryFunction::dateAdd(QueryFunction::now(), $seconds, 'SECOND');
    }

    /**
     * MAX() de una columna, con alias.
     */
    public static function maxOf(string $field, ?string $alias = null): QueryExpression
    {
        return new QueryExpression('MAX(' . DBmysql::quoteName($field) . ')', $alias);
    }

    /**
     * Segundos que faltan hasta el valor de una columna (o expresión).
     */
    public static function secondsUntil(string|QueryExpression $field): QueryExpression
    {
        return QueryFunction::timestampdiff('SECOND', QueryFunction::now(), $field, 'remaining');
    }

    /**
     * Filas con bloqueo vigente (columna `blocked` en el futuro).
     */
    public static function activeBlockCriteria(): array
    {
        return ['blocked' => ['>', QueryFunction::now()]];
    }

    /**
     * Fila con la marca de "bloqueada ahora" calculada por la base de datos,
     * para no mezclar el reloj de PHP con el de SQL.
     */
    public static function isBlockedNow(string $table, array $where): bool
    {
        global $DB;

        return count($DB->request([
            'SELECT' => 'id',
            'FROM'   => $table,
            'WHERE'  => $where + self::activeBlockCriteria(),
            'LIMIT'  => 1,
        ])) > 0;
    }

    /**
     * Recorta a la caducidad máxima los bloqueos heredados (p. ej. 2037).
     */
    public static function capLegacyBlocks(string $table): void
    {
        global $DB;

        $DB->update($table, [
            'blocked' => self::fromNow(self::DISTRIBUTED_DEFAULT),
        ], [
            'blocked' => ['>', self::fromNow(self::HARD_CEILING)],
        ]);
    }
}
