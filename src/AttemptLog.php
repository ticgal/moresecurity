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

namespace GlpiPlugin\Moresecurity;

use CommonDBTM;
use DBConnection;
use DBmysql;
use DisplayPreference;
use Dropdown;
use Glpi\Application\View\TemplateRenderer;
use Glpi\DBAL\QueryExpression;
use Glpi\DBAL\QueryFunction;
use Glpi\DBAL\QuerySubQuery;
use Glpi\Event;
use Html;
use Migration;
use RuntimeException;
use Throwable;
use User;

use function Safe\strtotime;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

/**
 * Registro de seguridad (solo anexar): una fila por cada intento de login o
 * de recuperación de contraseña fallido/solicitado y por cada denegación por
 * geobloqueo. Es la fuente del listado "Security log" y de las tarjetas del
 * dashboard; los contadores que deciden los bloqueos siguen en las tablas
 * login / loginip / lostpassword.
 */
class AttemptLog extends CommonDBTM
{
    public static string $rightname = 'plugin_moresecurity_attempt';

    public const EVENT_LOGIN       = 'login';
    public const EVENT_LOGIN_IP    = 'login_ip';
    public const EVENT_RESET_EMAIL = 'reset_email';
    public const EVENT_RESET_IP    = 'reset_ip';
    public const EVENT_LOGIN_GEO   = 'login_geo';

    private const SUMMARY_PAGE_SIZE = 20;

    // Tope de filas del registro por IP y hora: un origen que insiste no puede
    // inflar la tabla (SEV-03). Los contadores que deciden los bloqueos no
    // dependen del registro, así que el tope no debilita ninguna protección.
    private const MAX_ROWS_PER_IP_HOUR = 200;

    // Ventana de deduplicación de las denegaciones por geobloqueo (segundos).
    private const GEO_LOG_WINDOW = 300;

    public static function getTypeName($nb = 0): string
    {
        return _n('Attempt log', 'Attempt logs', $nb, 'moresecurity');
    }

    public static function getIcon(): string
    {
        return 'ti ti-list-details';
    }

    public static function getMenuName(): string
    {
        return __('Security log', 'moresecurity');
    }

    /**
     * El listado vive en front/attempt.php (con la barra de pestañas), no en
     * el front/attemptlog.php que GLPI calcularía por el nombre de la clase.
     */
    public static function getSearchURL($full = true): string
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        return ($full ? $CFG_GLPI['root_doc'] : '') . '/plugins/moresecurity/front/attempt.php';
    }

    public static function getSummaryURL(): string
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        return $CFG_GLPI['root_doc'] . '/plugins/moresecurity/front/attemptsummary.php';
    }

    /**
     * Registro de solo lectura: se escribe internamente y lo poda la acción
     * automática de retención; la UI no ofrece editar, borrar ni purgar.
     */
    /**
     * Mismo criterio que los registros del núcleo (Event, LogViewer): contiene
     * logins, emails e IPs, así que se exige reautenticación.
     */
    protected static function itemTypeRequiresReauthentication(): bool
    {
        return true;
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canUpdate(): bool
    {
        return false;
    }

    public static function canDelete(): bool
    {
        return false;
    }

    public static function canPurge(): bool
    {
        return false;
    }

    /**
     * Etiquetas legibles de los tipos de evento, indexadas por el valor de la
     * columna `event`.
     *
     * @return array<string, string>
     */
    public static function getTypeLabels(): array
    {
        return [
            self::EVENT_LOGIN       => __('Login', 'moresecurity'),
            self::EVENT_LOGIN_IP    => __('Login IP', 'moresecurity'),
            self::EVENT_RESET_EMAIL => __('Password reset', 'moresecurity'),
            self::EVENT_RESET_IP    => __('Password reset IP', 'moresecurity'),
            self::EVENT_LOGIN_GEO   => __('Login Geoblocked', 'moresecurity'),
        ];
    }

    private static function isLoginEvent(string $event): bool
    {
        return in_array($event, [self::EVENT_LOGIN, self::EVENT_LOGIN_IP, self::EVENT_LOGIN_GEO], true);
    }

    /**
     * Anota un evento. Nunca debe romper el flujo de login: un fallo al
     * escribir el registro se ignora.
     *
     * @param string $event      una de las constantes EVENT_*
     * @param string $identifier login o email tal como se envió (ya validado)
     * @param string $ip         IP del cliente, o '' si no se pudo resolver
     */
    public static function record(string $event, string $identifier, string $ip): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($ip !== '' && self::ipOverCap($ip)) {
            return;
        }

        try {
            $DB->insert(self::getTable(), [
                'event'      => $event,
                'identifier' => $identifier,
                'ip'         => $ip,
                'country'    => $ip !== '' ? Geoip::classifyIp($ip) : null,
                'users_id'   => self::resolveUserId($event, $identifier),
                'date'       => date('Y-m-d H:i:s'),
            ]);
        } catch (Throwable $e) {
            trigger_error('More Security: could not write the security log (' . $e->getMessage() . ')', E_USER_WARNING);
        }
    }

    /**
     * ¿Esta IP ya ha escrito el máximo de filas de la última hora?
     */
    private static function ipOverCap(string $ip): bool
    {
        return self::countInBucket(
            $ip,
            ['date' => ['>', QueryFunction::dateSub(QueryFunction::now(), 1, 'HOUR')]],
            self::MAX_ROWS_PER_IP_HOUR,
        ) >= self::MAX_ROWS_PER_IP_HOUR;
    }

    /**
     * Filas del registro del mismo origen que $ip (IPv4 exacta; IPv6 por
     * prefijo /64, igual que los contadores de bloqueo), contadas hasta
     * $limit. Una IPv6 que rota dentro de su /64 no esquiva el tope.
     */
    private static function countInBucket(string $ip, array $criteria, int $limit): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        if (!str_contains($ip, ':')) {
            $row = $DB->request(['COUNT' => 'c', 'FROM' => self::getTable(), 'WHERE' => ['ip' => $ip] + $criteria])->current();

            return (int) $row['c'];
        }

        // El texto de una IPv6 comienza por su primer grupo: se acota por ahí
        // y se confirma el /64 en PHP.
        $bucket = Limiter::bucketIp($ip);
        $count  = 0;
        $rows   = $DB->request([
            'SELECT' => 'ip',
            'FROM'   => self::getTable(),
            'WHERE'  => ['ip' => ['LIKE', explode(':', $ip)[0] . ':%']] + $criteria,
            'LIMIT'  => $limit * 20,
        ]);
        foreach ($rows as $row) {
            if (Limiter::bucketIp($row['ip']) === $bucket && ++$count >= $limit) {
                break;
            }
        }

        return $count;
    }

    /**
     * Intento de login fallido: una fila por cuenta y otra por IP, para que
     * las tarjetas "IPs atacantes" y "cuentas atacadas" cuenten por separado.
     */
    public static function recordFailedLogin(string $login, string $ip): void
    {
        self::record(self::EVENT_LOGIN, $login, $ip);
        if ($ip !== '') {
            self::record(self::EVENT_LOGIN_IP, $login, $ip);
        }
    }

    /**
     * Solicitud de recuperación de contraseña admitida a trámite.
     */
    public static function recordResetRequest(string $email, string $ip): void
    {
        self::record(self::EVENT_RESET_EMAIL, $email, $ip);
        if ($ip !== '') {
            self::record(self::EVENT_RESET_IP, $email, $ip);
        }
    }

    /**
     * Denegación por geobloqueo: solo informativa, ningún contador depende
     * de ella.
     */
    public static function logGeoBlock(string $ip, string $identifier, string $country_code): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        // Como mucho una fila (y un evento) por IP y ventana: un origen
        // denegado no puede inflar el registro ni `glpi_events` (SEV-02).
        $recent = self::countInBucket($ip, [
            'event' => self::EVENT_LOGIN_GEO,
            'date'  => ['>', QueryFunction::dateSub(QueryFunction::now(), self::GEO_LOG_WINDOW, 'SECOND')],
        ], 1);
        if ($recent > 0) {
            return;
        }

        try {
            $DB->insert(self::getTable(), [
                'event'      => self::EVENT_LOGIN_GEO,
                'identifier' => $identifier,
                'ip'         => $ip,
                'country'    => $country_code,
                'users_id'   => self::resolveUserId(self::EVENT_LOGIN_GEO, $identifier),
                'date'       => date('Y-m-d H:i:s'),
            ]);
        } catch (Throwable $e) {
            trigger_error('More Security: could not write the security log (' . $e->getMessage() . ')', E_USER_WARNING);
        }

        // El mensaje acaba en una columna `text` del núcleo (se muestra como HTML
        // enriquecido si es largo) y en un fichero de log: corto y sin marcado.
        $shown = mb_substr(strtr($identifier, ['<' => '‹', '>' => '›']), 0, 64);

        Event::log(
            0,
            "system",
            3,
            "login",
            sprintf(
                __('Blocked login attempt for %1$s from IP %2$s (geoblocked: %3$s)', 'moresecurity'),
                $shown,
                $ip,
                $country_code,
            ),
        );
    }

    /**
     * Empareja el identificador con una cuenta real para poder mostrar un
     * enlace de usuario. Devuelve null si no hay coincidencia (lo normal en
     * tráfico de ataque).
     */
    private static function resolveUserId(string $event, string $identifier): ?int
    {
        if ($identifier === '') {
            return null;
        }

        $user    = new User();
        $matched = self::isLoginEvent($event)
            ? $user->getFromDBbyName($identifier)
            : $user->getFromDBbyEmail($identifier);

        return $matched ? (int) $user->fields['id'] : null;
    }

    public function rawSearchOptions(): array
    {
        $tab = parent::rawSearchOptions();

        $tab[] = [
            'id'            => '16',
            'table'         => $this->getTable(),
            'field'         => 'id',
            'name'          => __('ID'),
            'datatype'      => 'number',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id'         => '10',
            'table'      => $this->getTable(),
            'field'      => 'event',
            'name'       => __('Type', 'moresecurity'),
            'datatype'   => 'specific',
            'searchtype' => ['equals', 'notequals'],
        ];

        $tab[] = [
            'id'       => '11',
            'table'    => $this->getTable(),
            'field'    => 'identifier',
            'name'     => __('Identifier'),
            // 'text' haría que el núcleo muestre como HTML enriquecido (con enlaces e
            // imágenes) los valores de más de 250 caracteres: el identificador lo
            // escribe un anónimo.
            'datatype' => 'string',
        ];

        $tab[] = [
            'id'       => '12',
            'table'    => $this->getTable(),
            'field'    => 'ip',
            'name'     => __('IP'),
            'datatype' => 'text',
        ];

        $tab[] = [
            'id'        => '13',
            'table'     => User::getTable(),
            'field'     => 'name',
            'linkfield' => 'users_id',
            'name'      => User::getTypeName(1),
            'datatype'  => 'dropdown',
        ];

        $tab[] = [
            'id'       => '14',
            'table'    => $this->getTable(),
            'field'    => 'date',
            'name'     => __('Date'),
            'datatype' => 'datetime',
        ];

        $tab[] = [
            'id'                  => '20',
            'table'               => $this->getTable(),
            'field'               => 'country',
            'name'                => __('Country', 'moresecurity'),
            'datatype'            => 'specific',
            'searchtype'          => ['equals', 'notequals'],
            'searchequalsonfield' => true,
        ];

        // Login/Email leen la misma columna `identifier` que la opción 11,
        // separadas por tipo de evento en getSpecificValueToDisplay();
        // `additionalfields` trae `event` para poder hacerlo fila a fila.
        $tab[] = [
            'id'               => '17',
            'table'            => $this->getTable(),
            'field'            => 'identifier',
            'name'             => __('Login'),
            'datatype'         => 'specific',
            'additionalfields' => ['event'],
        ];

        $tab[] = [
            'id'               => '18',
            'table'            => $this->getTable(),
            'field'            => 'identifier',
            'name'             => _n('Email', 'Emails', 1),
            'datatype'         => 'specific',
            'additionalfields' => ['event'],
        ];

        return $tab;
    }

    public static function getSpecificValueToDisplay($field, $values, array $options = [])
    {
        if ($field === 'event') {
            $value = is_array($values) ? ($values['event'] ?? '') : $values;
            $value = is_scalar($value) ? (string) $value : '';
            return htmlescape(self::getTypeLabels()[$value] ?? $value);
        }

        if ($field === 'country') {
            $value = is_array($values) ? ($values['country'] ?? null) : $values;
            $value = is_scalar($value) ? (string) $value : null;
            return htmlescape(Geoip::getCountryDisplayName($value ?: null));
        }

        if ($field === 'identifier' && isset($options['searchopt']['id'])) {
            $so_id = (int) $options['searchopt']['id'];
            if (in_array($so_id, [17, 18], true)) {
                $identifier = is_array($values) ? ($values['identifier'] ?? '') : $values;
                $event      = is_array($values) ? (string) ($values['event'] ?? '') : '';

                // Una celda vacía debe devolver '&nbsp;', no '': GLPI trata ''
                // como "sin sobrescribir" y muestra el valor en crudo.
                if ($identifier === '' || $identifier === null) {
                    return '&nbsp;';
                }

                $is_login = self::isLoginEvent($event);
                if ($so_id === 17) {
                    return $is_login ? htmlescape($identifier) : '&nbsp;';
                }

                return !$is_login ? htmlescape($identifier) : '&nbsp;';
            }
        }

        return parent::getSpecificValueToDisplay($field, $values, $options);
    }

    public static function getSpecificValueToSelect($field, $name = '', $values = '', array $options = [])
    {
        if ($field === 'event') {
            $value = is_array($values) ? ($values['event'] ?? '') : $values;
            $value = is_scalar($value) ? (string) $value : '';

            return Dropdown::showFromArray($name, self::getTypeLabels(), [
                'value'   => $value,
                'display' => false,
            ] + $options);
        }

        if ($field === 'country') {
            $value = is_array($values) ? ($values['country'] ?? '') : $values;
            $value = is_scalar($value) ? (string) $value : '';

            return Dropdown::showFromArray($name, self::getCountryFilterChoices(), [
                'value'   => $value,
                'display' => false,
            ] + $options);
        }

        return parent::getSpecificValueToSelect($field, $name, $values, $options);
    }

    /**
     * Opciones del filtro "País": primero Private/Reserved/Unknown, después
     * cada país presente en la tabla ordenado por nombre.
     *
     * @return array<string,string>
     */
    private static function getCountryFilterChoices(): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $choices = [];
        foreach (Geoip::getNonCountrySentinels() as $sentinel) {
            $choices[$sentinel] = Geoip::getCountryDisplayName($sentinel);
        }

        $codes = array_column(iterator_to_array($DB->request([
            'SELECT'  => ['country'],
            'FROM'    => self::getTable(),
            'WHERE'   => ['country' => ['NOT IN', Geoip::getNonCountrySentinels()]],
            'GROUPBY' => ['country'],
        ])), 'country');

        $countries = [];
        foreach ($codes as $code) {
            if ($code === null) {
                continue;
            }
            $countries[$code] = Geoip::getCountryDisplayName($code);
        }
        asort($countries);

        return $choices + $countries;
    }

    /**
     * Listado por defecto: el intento más reciente primero. Este itemtype no
     * tiene `name`, así que la opción 1 (orden implícito) no existe y sin esto
     * el listado saldría vacío al abrirlo.
     */
    public static function getDefaultSearchRequest(): array
    {
        return [
            'sort'  => 14,
            'order' => 'DESC',
        ];
    }

    /**
     * Pestaña "Summary": intentos agrupados por tipo, identificador e IP.
     */
    public static function showSummary(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $table = self::getTable();
        $start = max(0, (int) ($_GET['start'] ?? 0));

        $total = (int) ($DB->request([
            'COUNT' => 'cpt',
            'FROM'  => new QuerySubQuery([
                'SELECT'  => ['event', 'identifier', 'ip'],
                'FROM'    => $table,
                'GROUPBY' => ['event', 'identifier', 'ip'],
            ], 'grouped'),
        ])->current()['cpt'] ?? 0);

        $result = $DB->request([
            'SELECT'  => [
                'event',
                'identifier',
                'ip',
                new QueryExpression('MAX(' . $DB::quoteName('country') . ') AS ' . $DB::quoteName('country')),
                new QueryExpression('MAX(' . $DB::quoteName('users_id') . ') AS ' . $DB::quoteName('users_id')),
                new QueryExpression('COUNT(*) AS ' . $DB::quoteName('try_count')),
                new QueryExpression('MAX(' . $DB::quoteName('date') . ') AS ' . $DB::quoteName('last_try')),
            ],
            'FROM'    => $table,
            'GROUPBY' => ['event', 'identifier', 'ip'],
            'ORDER'   => ['last_try DESC'],
            'START'   => $start,
            'LIMIT'   => self::SUMMARY_PAGE_SIZE,
        ]);

        $labels = self::getTypeLabels();
        $rows   = [];
        foreach ($result as $row) {
            $is_login = self::isLoginEvent($row['event']);
            $user     = '';
            if (!empty($row['users_id'])) {
                $u = new User();
                if ($u->getFromDB((int) $row['users_id'])) {
                    $user = $u->getLink();
                }
            }
            $rows[] = [
                'type'      => $labels[$row['event']] ?? $row['event'],
                'login'     => $is_login ? $row['identifier'] : '',
                'email'     => !$is_login ? $row['identifier'] : '',
                'user'      => $user,
                'ip'        => $row['ip'],
                'country'   => Geoip::getCountryDisplayName($row['country'] ?: null),
                'try_count' => (int) $row['try_count'],
                'last_try'  => Html::convDateTime($row['last_try']),
            ];
        }

        TemplateRenderer::getInstance()->display('@moresecurity/attempt_summary.html.twig', [
            'rows' => $rows,
        ]);

        Html::printPager($start, $total, self::getSummaryURL(), '');
    }

    /**
     * Top de IPs por intentos (login + recuperación) dentro de una ventana.
     * Son los orígenes del ataque (candidatas a bloqueo).
     *
     * @return array [['ip' => string, 'total' => int], ...] en orden descendente
     */
    public static function getTopAttackingIps(int $hours, int $limit = 10): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $since = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));

        $result = $DB->request([
            'SELECT'  => ['ip', new QueryExpression('COUNT(*) AS total')],
            'FROM'    => self::getTable(),
            'WHERE'   => [
                'event' => [self::EVENT_LOGIN_IP, self::EVENT_RESET_IP],
                'date'  => ['>', $since],
            ],
            'GROUPBY' => ['ip'],
            'ORDER'   => ['total DESC'],
            'LIMIT'   => $limit,
        ]);

        return iterator_to_array($result, false);
    }

    /**
     * Top de identificadores (usuarios/emails) atacados, existan o no. Son
     * los objetivos, no los ofensores: nunca presentarlos como lista de
     * bloqueo.
     *
     * @return array [['identifier' => string, 'total' => int], ...] en orden descendente
     */
    public static function getMostTargetedAccounts(int $hours, int $limit = 10): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $since = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));

        $result = $DB->request([
            'SELECT'  => ['identifier', new QueryExpression('COUNT(*) AS total')],
            'FROM'    => self::getTable(),
            'WHERE'   => [
                'event' => [self::EVENT_LOGIN, self::EVENT_RESET_EMAIL],
                'date'  => ['>', $since],
            ],
            'GROUPBY' => ['identifier'],
            'ORDER'   => ['total DESC'],
            'LIMIT'   => $limit,
        ]);

        return iterator_to_array($result, false);
    }

    /**
     * Intentos por país y tipo de evento dentro de una ventana, para las
     * tarjetas "Top offending countries". Se ordena solo por total.
     *
     * @return array{countries: array<string,array<string,int>>, events: string[]}
     */
    public static function getTopCountriesByType(int $hours, int $limit = 10): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $since = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));

        $result = $DB->request([
            'SELECT'  => ['country', 'event', new QueryExpression('COUNT(*) AS total')],
            'FROM'    => self::getTable(),
            'WHERE'   => [
                'NOT'  => ['country' => null],
                'date' => ['>', $since],
            ],
            'GROUPBY' => ['country', 'event'],
        ]);

        $matrix = [];
        $totals = [];
        $events = [];
        foreach ($result as $row) {
            $country = $row['country'];
            $matrix[$country][$row['event']] = (int) $row['total'];
            $totals[$country] = ($totals[$country] ?? 0) + (int) $row['total'];
            if (!in_array($row['event'], $events, true)) {
                $events[] = $row['event'];
            }
        }

        arsort($totals);

        $countries = [];
        foreach (array_slice(array_keys($totals), 0, $limit) as $country) {
            $countries[$country] = $matrix[$country];
        }

        return ['countries' => $countries, 'events' => $events];
    }

    /**
     * Retención: borra por lotes los registros más antiguos que
     * $retention_days. Devuelve cuántos se borraron.
     */
    public static function purge(int $retention_days, int $batch = 5000, int $max_batches = 100): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($retention_days <= 0) {
            return 0;
        }

        $cutoff  = ['date' => ['<', QueryFunction::dateSub(QueryFunction::now(), $retention_days, 'DAY')]];
        $deleted = 0;
        for ($i = 0; $i < $max_batches; $i++) {
            // DBmysql::delete() no admite LIMIT: se eligen los ids del lote y se
            // borran por clave, igual de acotado y sin SQL en bruto.
            $ids = array_column(iterator_to_array($DB->request([
                'SELECT' => 'id',
                'FROM'   => self::getTable(),
                'WHERE'  => $cutoff,
                'LIMIT'  => $batch,
            ]), false), 'id');
            if ($ids === []) {
                break;
            }
            $DB->delete(self::getTable(), ['id' => $ids]);
            $deleted += count($ids);
            if (count($ids) < $batch) {
                break;
            }
        }

        return $deleted;
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
				`event` varchar(20) NOT NULL,
				`identifier` varchar(255) DEFAULT NULL,
				`ip` varchar(45) NOT NULL DEFAULT '',
				`country` varchar(10) DEFAULT NULL,
				`users_id` int {$default_key_sign} DEFAULT NULL,
				`date` TIMESTAMP NULL DEFAULT NULL,
				PRIMARY KEY (`id`),
				KEY `event` (`event`),
				KEY `identifier` (`identifier`),
				KEY `ip` (`ip`),
				KEY `country` (`country`),
				KEY `users_id` (`users_id`),
				KEY `date` (`date`),
				KEY `date_country_event` (`date`, `country`, `event`)
			) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";

            $DB->doQuery($query) or throw new RuntimeException($DB->error());
        }

        self::installDefaultDisplayPreferences();
    }

    /**
     * Columnas por defecto del listado (glpi_displaypreferences, users_id=0).
     */
    private static function installDefaultDisplayPreferences(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $existing_ids = array_column(iterator_to_array($DB->request([
            'FROM'  => DisplayPreference::getTable(),
            'WHERE' => ['itemtype' => self::class, 'users_id' => 0],
        ])), 'num');

        $rank = count($existing_ids);
        foreach ([14, 10, 17, 18, 13, 12, 20] as $search_option_id) {
            if (in_array($search_option_id, $existing_ids, true)) {
                continue;
            }
            $rank++;
            $DB->insert(DisplayPreference::getTable(), [
                'itemtype' => self::class,
                'num'      => $search_option_id,
                'rank'     => $rank,
                'users_id' => 0,
            ]);
        }
    }

    public static function uninstall(Migration $migration): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $migration->dropTable(self::getTable());
        $DB->delete(DisplayPreference::getTable(), ['itemtype' => self::class]);
    }
}
