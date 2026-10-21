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

    // Duraciones de bloqueo reales: 0 las dejaría inefectivas (MS-10). Los
    // "max_*" sí admiten 0 con el significado "sin tope de backoff".
    private const POSITIVE_TIME_FIELDS = ['time_blocked', 'ip_time_blocked', 'time_reset'];

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
     * @param  CommonGLPI $item
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
     * @param  CommonGLPI $item
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
        global $CFG_GLPI;

        $config = self::getInstance();

        $filters = [];
        foreach ((array) ($_GET['filters'] ?? []) as $col => $value) {
            if (is_string($col) && is_string($value) && $value !== '') {
                $filters[$col] = mb_substr($value, 0, 255);
            }
        }
        $blocks = self::getActiveBlocks(
            $filters,
            is_string($_GET['sort'] ?? null) ? $_GET['sort'] : null,
            ($_GET['order'] ?? 'ASC') === 'DESC' ? 'DESC' : 'ASC',
            max(1, (int) ($_SESSION['glpilist_limit'] ?? 15)),
            max(0, (int) ($_GET['start'] ?? 0))
        );

        $template = "@moresecurity/forms/config.form.html.twig";
        TemplateRenderer::getInstance()->display($template, [
            'item' => $config,
            'geoblock_country_choices'    => PluginMoresecurityGeoip::getCountryNames(),
            'geoblock_countries_selected' => PluginMoresecurityLimiter::parseList((string) ($config->fields['geoblock_countries'] ?? '')),
            'geoip_database_ready'        => file_exists(PluginMoresecurityGeoip::getDatabasePath()),
            // El login por credenciales de la API REST no pasa por el plugin.
            'api_login_unprotected'       => !empty($CFG_GLPI['enable_api']) && !empty($CFG_GLPI['enable_api_login_credentials']),
            'blocked_filters'  => $blocks['filters'],
            'blocked_filter_query' => http_build_query(['filters' => $blocks['filters']]),
            'blocked_sort'     => $blocks['sort'],
            'blocked_order'    => $blocks['order'],
            'blocked_start'    => $blocks['start'],
            'blocked_limit'    => $blocks['limit'],
            'all_blocked'      => $blocks['entries'],
            'all_blocked_total'  => $blocks['total'],
            'blocked_filtered_number' => $blocks['filtered'],
            'blocked_filtered_keys'   => $blocks['keys'],
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
                $min = in_array($field, self::POSITIVE_TIME_FIELDS, true) ? 1 : 0;
                $input[$field] = self::clampInput($input[$field], $min, self::MAX_BLOCK_SECONDS, max($min, (int) $this->fields[$field]));
            }
        }

        // Geobloqueo: modo y países se validan en servidor (el desplegable solo
        // ofrece códigos reales, pero el POST puede estar manipulado).
        if (
            array_key_exists('geoblock_mode', $input)
            && !in_array($input['geoblock_mode'], PluginMoresecurityGeoip::MODES, true)
        ) {
            unset($input['geoblock_mode']);
        }
        if (array_key_exists('geoblock_countries', $input)) {
            $values = is_array($input['geoblock_countries'])
                ? $input['geoblock_countries']
                : explode(',', (string) $input['geoblock_countries']);
            $valid  = array_keys(PluginMoresecurityGeoip::getCountryNames());
            $input['geoblock_countries'] = implode(',', array_intersect(array_map('strval', $values), $valid));
        }

        // "Solo estos países" sin ningún país rechazaría todos los logins de
        // direcciones enrutables: no se permite guardar esa combinación.
        $mode      = $input['geoblock_mode'] ?? ($this->fields['geoblock_mode'] ?? PluginMoresecurityGeoip::MODE_DISABLED);
        $countries = $input['geoblock_countries'] ?? ($this->fields['geoblock_countries'] ?? '');
        if ($mode === PluginMoresecurityGeoip::MODE_ALLOW && trim((string) $countries) === '') {
            $input['geoblock_mode'] = PluginMoresecurityGeoip::MODE_DISABLED;
            Session::addMessageAfterRedirect(
                __('Geoblocking was not enabled: "Only allow these countries" needs at least one country.', 'moresecurity'),
                true,
                WARNING
            );
        }

        // Proxies de confianza: solo IPs válidas, el resto se descarta.
        if (array_key_exists('trusted_proxies', $input)) {
            $input['trusted_proxies'] = self::sanitizeIpList($input['trusted_proxies']);
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
     * Bloqueos vigentes de cuentas, IPs y correos de recuperación unificados
     * en una sola lista filtrable, ordenable y paginada ("Active blocks").
     * Los tres orígenes están acotados (100 filas cada uno), así que filtrar,
     * ordenar y paginar en PHP es barato y deja el total y las claves de
     * "Desbloquear todos" coherentes con el filtro aplicado.
     *
     * @param array<string, string> $filters subcadena por columna visible
     * @return array{entries: array, total: int, filtered: int, keys: string[], filters: array, sort: ?string, order: string, start: int, limit: int}
     */
    public static function getActiveBlocks(array $filters, ?string $sort, string $order, int $limit, int $start): array
    {
        $labels = PluginMoresecurityAttemptLog::getTypeLabels();
        $rows   = [];

        foreach (PluginMoresecurityLogin::getBlocked() as $row) {
            $rows[] = self::mapBlockRow('account', PluginMoresecurityAttemptLog::EVENT_LOGIN, $labels, $row, 'login', 'login');
        }
        foreach (PluginMoresecurityLoginip::getBlocked() as $row) {
            $rows[] = self::mapBlockRow('ip', PluginMoresecurityAttemptLog::EVENT_LOGIN_IP, $labels, $row, 'ip', 'ip');
        }
        foreach (PluginMoresecurityLostpassword::getBlocked() as $row) {
            $rows[] = self::mapBlockRow('email', PluginMoresecurityAttemptLog::EVENT_RESET_EMAIL, $labels, $row, 'email', 'email');
        }
        $total = count($rows);

        $rows = array_values(array_filter($rows, static function (array $row) use ($filters): bool {
            foreach ($filters as $col => $needle) {
                if (!array_key_exists($col, $row['text'])) {
                    continue;
                }
                if (!str_contains(mb_strtolower($row['text'][$col]), mb_strtolower($needle))) {
                    return false;
                }
            }
            return true;
        }));

        $sortable = ['type', 'user', 'login', 'email', 'ip', 'blocked_at', 'remaining'];
        if ($sort === null || !in_array($sort, $sortable, true)) {
            $sort = null;
        }
        $key = $sort === null ? 'remaining' : $sort;
        usort($rows, static function (array $a, array $b) use ($key, $sort, $order): int {
            $cmp = ($a['sort'][$key] ?? '') <=> ($b['sort'][$key] ?? '');
            return $sort !== null && $order === 'DESC' ? -$cmp : $cmp;
        });

        $filtered = count($rows);
        $keys     = array_column($rows, 'key');
        $start    = $start >= $filtered ? 0 : $start;

        $entries = [];
        foreach (array_slice($rows, $start, $limit) as $row) {
            $entries[] = $row['display'];
        }

        return [
            'entries'  => $entries,
            'total'    => $total,
            'filtered' => $filtered,
            'keys'     => $keys,
            'filters'  => $filters,
            'sort'     => $sort,
            'order'    => $order,
            'start'    => $start,
            'limit'    => $limit,
        ];
    }

    /**
     * Una fila de bloqueo en forma de visualización: `display` (lo que pinta
     * la tabla), `text` (valores planos para filtrar), `sort` (valores
     * crudos para ordenar) y `key` ("tipo|valor", como espera unblock()).
     *
     * @param array<string, string> $labels
     * @param array<string, mixed>  $row
     * @return array{key: string, display: array<string, string>, text: array<string, string>, sort: array<string, mixed>}
     */
    private static function mapBlockRow(string $type, string $event, array $labels, array $row, string $field, string $kind): array
    {
        $value    = (string) $row[$field];
        $key      = $type . '|' . $value;
        $login    = $kind === 'login' ? $value : '';
        $email    = $kind === 'email' ? $value : '';
        $ip       = $kind === 'ip' ? $value : '';
        // Segundos restantes calculados por la base de datos (la misma que decide
        // el bloqueo): PHP y MariaDB pueden tener zonas horarias distintas.
        $seconds  = $row['remaining'] !== null ? (int) $row['remaining'] : null;
        $last_try = $row['last_try'] !== null ? (string) $row['last_try'] : '';

        $user_name = '';
        $user_html = '';
        if ($kind !== 'ip') {
            $user = new User();
            $found = $kind === 'login' ? $user->getFromDBbyName($value) : $user->getFromDBbyEmail($value);
            if ($found) {
                $user_name = (string) $user->fields['name'];
                $user_html = '<a href="' . htmlescape(User::getFormURLWithID((int) $user->fields['id'])) . '">'
                    . htmlescape($user_name) . '</a>';
            }
        }

        $remaining = '';
        if ($seconds !== null) {
            $remaining = $seconds > 0 ? Html::timestampToString($seconds) : __('Expired', 'moresecurity');
        }
        $blocked_at = $last_try !== '' ? Html::convDateTime($last_try) : '';
        $type_label = $labels[$event] ?? $event;

        return [
            'key'     => $key,
            'display' => [
                'select'     => '<input type="checkbox" class="form-check-input ms-unblock-checkbox" name="unblock_items[]" value="'
                    . htmlescape($key) . '" />',
                'type'       => $type_label,
                'user'       => $user_html,
                'login'      => $login,
                'email'      => $email,
                'ip'         => $ip,
                'blocked_at' => $blocked_at,
                'remaining'  => $remaining,
                'action'     => '<button type="submit" name="unblock_item" value="' . htmlescape($key)
                    . '" class="btn btn-sm btn-outline-danger"><i class="ti ti-lock-open"></i> '
                    . htmlescape(__('Unblock', 'moresecurity')) . '</button>',
            ],
            'text'    => [
                'type' => $type_label, 'user' => $user_name, 'login' => $login, 'email' => $email,
                'ip' => $ip, 'blocked_at' => $blocked_at, 'remaining' => $remaining,
            ],
            'sort'    => [
                'type' => $type_label, 'user' => $user_name, 'login' => $login, 'email' => $email,
                'ip' => $ip, 'blocked_at' => $last_try, 'remaining' => $seconds ?? 0,
            ],
        ];
    }

    /**
     * Desbloqueo administrativo (MS-03). El llamador debe haber comprobado
     * el derecho `config` UPDATE y el token CSRF. Se audita en el historial.
     */
    public static function unblock(mixed $type, mixed $value): bool
    {
        if (!is_string($type) || !is_string($value) || $value === '' || strlen($value) > 255) {
            return false;
        }

        $done = match ($type) {
            'account' => PluginMoresecurityLogin::unblock($value),
            'ip'      => PluginMoresecurityLoginip::unblock($value),
            'email'   => PluginMoresecurityLostpassword::unblock($value),
            default   => false,
        };
        if ($done) {
            Log::history(1, 'Config', [0, '', sprintf('unblock %s: %s', $type, $value)]);
        }

        return $done;
    }

    /**
     * Lista de IPs separada por comas: descarta (avisando) lo que no sea una
     * IPv4/IPv6 válida y devuelve la lista normalizada.
     */
    private static function sanitizeIpList(mixed $value): string
    {
        if (!is_string($value)) {
            return '';
        }

        $valid = [];
        foreach (PluginMoresecurityLimiter::parseList($value) as $entry) {
            if (filter_var($entry, FILTER_VALIDATE_IP) !== false) {
                $valid[] = PluginMoresecurityLimiter::canonicalIp($entry);
            } else {
                Session::addMessageAfterRedirect(
                    sprintf(__('Ignored invalid IP entry: %s', 'moresecurity'), htmlescape($entry)),
                    false,
                    ERROR
                );
            }
        }

        return implode(',', array_unique($valid));
    }

    /**
     * Desbloqueo masivo. Cada elemento es "tipo|valor" (mismo formato que
     * construye la plantilla). Devuelve cuántos se desbloquearon.
     *
     * @param mixed $items
     */
    public static function unblockMany(mixed $items): int
    {
        if (!is_array($items)) {
            return 0;
        }

        $done = 0;
        foreach (array_slice($items, 0, 1000) as $item) {
            if (!is_string($item) || !str_contains($item, '|')) {
                continue;
            }
            [$type, $value] = explode('|', $item, 2);
            if (self::unblock($type, $value)) {
                $done++;
            }
        }

        return $done;
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
     * @param  Migration $migration
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
			`trusted_proxies` text DEFAULT NULL,
			`geoblock_mode` varchar(255) NOT NULL DEFAULT 'disabled',
			`geoblock_countries` text DEFAULT NULL,
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

            //2.3.0
            $migration->addField($table, 'trusted_proxies', 'text');
            $migration->addField($table, 'geoblock_mode', 'string', ['value' => 'disabled']);
            $migration->addField($table, 'geoblock_countries', 'text');
            $migration->migrationOneTable($table);
        }
    }

    public static function uninstall(Migration $migration): void
    {
        $migration->dropTable(self::getTable());
    }
}
