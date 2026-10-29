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

use CommonDropdown;
use DBConnection;
use Dropdown;
use Migration;
use RuntimeException;
use Session;

use function Safe\inet_ntop;
use function Safe\inet_pton;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

class Whitelist extends CommonDropdown
{
    public bool $dohistory = true;

    // Exención de un control de seguridad global: requiere el mismo
    // derecho que la config del plugin, no el genérico 'dropdown' (UC-05).
    public static string $rightname = 'config';

    /**
     * Same re-authentication the core demands for its own configuration.
     */
    protected static function itemTypeRequiresReauthentication(): bool
    {
        return true;
    }

    public bool $can_be_translated = false;

    public const IP = 1;

    public static function getTypeName($nb = 0): string
    {
        return _n('Whitelist', 'Whitelists', $nb, 'moresecurity');
    }

    public static function getIcon(): string
    {
        return 'ti ti-shield-check';
    }

    public static function canCreate(): bool
    {
        return static::canUpdate();
    }

    public static function canPurge(): bool
    {
        return static::canUpdate();
    }

    public function getAdditionalFields(): array
    {
        return [
            [
                'name'  => 'value',
                'label' => __('Value'),
                'type'  => 'text',
                'list'  => true,
            ],
            [
                'name'  => 'type',
                'label' => _n('Type', 'Types', 1),
                'type'  => '',
                'list'  => true,
            ],
        ];
    }

    public function rawSearchOptions(): array
    {
        $tab = parent::rawSearchOptions();

        $tab[] = [
            'id'       => '11',
            'table'    => $this->getTable(),
            'field'    => 'value',
            'name'     => __('Value'),
            'datatype' => 'text',
        ];

        $tab[] = [
            'id'         => '12',
            'table'      => $this->getTable(),
            'field'      => 'type',
            'name'       => _n('Type', 'Types', 1),
            'searchtype' => ['equals', 'notequals'],
            'datatype'   => 'specific',
        ];

        return $tab;
    }

    public function prepareInputForAdd($input): array|false
    {
        return $this->validateAndNormalizeIpInput($input);
    }

    public function prepareInputForUpdate($input): array|false
    {
        return $this->validateAndNormalizeIpInput($input);
    }

    /**
     * Valida y normaliza el valor de una entrada de tipo IP (UC-07): un
     * valor que no sea una IP/CIDR válida se rechaza en vez de guardarse
     * tal cual, y se normaliza para que isWhitelisted() pueda compararlo
     * de forma fiable (sin espacios, IPv6 en forma canónica).
     */
    private function validateAndNormalizeIpInput($input): array|false
    {
        if ((!isset($input['name']) || empty($input['name'])) && isset($input['value'])) {
            $input['name'] = $input['value'];
        }

        $type = $input['type'] ?? ($this->fields['type'] ?? null);
        if ((int) $type === self::IP && isset($input['value'])) {
            $normalized = self::normalizeIpOrCidr((string) $input['value']);
            if ($normalized === null) {
                Session::addMessageAfterRedirect(
                    __('Invalid IP address or CIDR range.', 'moresecurity'),
                    false,
                    ERROR,
                );
                return false;
            }
            $input['value'] = $normalized;
            $input['name']  = $normalized;
        }

        return $input;
    }

    /**
     * Valida una IP o un CIDR ("ip/prefijo") y la devuelve en forma
     * canónica, o null si no es válida. Soporta IPv4 e IPv6.
     */
    /**
     * inet_pton() sin avisos de PHP: null si no es una IPv4/IPv6 válida.
     */
    private static function pack(string $ip): ?string
    {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = inet_pton($ip);
        // IPv4 mapeada en IPv6: se compara como la IPv4 que lleva.
        if (strlen($packed) === 16 && str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
            return substr($packed, 12);
        }

        return $packed;
    }

    private static function normalizeIpOrCidr(string $value): ?string
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }

        if (str_contains($value, '/')) {
            [$address, $prefix] = explode('/', $value, 2);
            $packed = self::pack($address);
            if ($packed === null || !ctype_digit($prefix)) {
                return null;
            }

            $prefix = (int) $prefix;
            if ($prefix < 0 || $prefix > strlen($packed) * 8) {
                return null;
            }

            return inet_ntop($packed) . '/' . $prefix;
        }

        $packed = self::pack($value);
        if ($packed === null) {
            return null;
        }

        return inet_ntop($packed);
    }

    public static function getTypes(): array
    {
        return [
            self::IP => __('IP'),
        ];
    }

    public static function dropdownType(string $name, array $options = []): string
    {
        $params = [
            'value'   => 0,
            'display' => true,
        ];
        $params = array_merge($params, $options);
        return Dropdown::showFromArray($name, self::getTypes(), $params);
    }

    public function displaySpecificTypeField($ID, $field = [], array $options = []): void
    {
        if ($field['name'] == 'type') {
            self::dropdownType($field['name'], [
                'value' => $this->fields['type'],
                'width' => '100%',
            ]);
        }
    }

    public static function getSpecificValueToDisplay($field, $values, array $options = []): string
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        if ($field === 'type') {
            $types = self::getTypes();
            return htmlescape($types[$values[$field]] ?? '');
        }
        return parent::getSpecificValueToDisplay($field, $values, $options);
    }

    public static function isWhitelisted(string $ip): bool
    {
        $packed_ip = self::pack($ip);
        if ($packed_ip === null) {
            return false;
        }

        $entries = getAllDataFromTable(self::getTable(), ['type' => self::IP]);
        foreach ($entries as $entry) {
            if (self::entryMatchesIp($entry['value'], $packed_ip)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compara una entrada de whitelist (IP exacta o CIDR "ip/prefijo") con
     * una IP ya empaquetada (inet_pton). Soporta IPv4 e IPv6 sin mezclarlos.
     */
    private static function entryMatchesIp(string $entry_value, string $packed_ip): bool
    {
        $entry_value = trim($entry_value);

        if (!str_contains($entry_value, '/')) {
            $packed_entry = self::pack($entry_value);
            return $packed_entry !== null && $packed_entry === $packed_ip;
        }

        [$network, $prefix] = explode('/', $entry_value, 2);
        $packed_network = self::pack($network);
        if ($packed_network === null || !ctype_digit($prefix)) {
            return false;
        }

        return self::packedIpInCidr($packed_ip, $packed_network, (int) $prefix);
    }

    private static function packedIpInCidr(string $packed_ip, string $packed_network, int $prefix): bool
    {
        if (strlen($packed_ip) !== strlen($packed_network)) {
            return false; // no mezclar IPv4 y IPv6
        }

        if ($prefix < 0 || $prefix > strlen($packed_ip) * 8) {
            return false;
        }

        $full_bytes = intdiv($prefix, 8);
        if ($full_bytes > 0 && substr($packed_ip, 0, $full_bytes) !== substr($packed_network, 0, $full_bytes)) {
            return false;
        }

        $remaining_bits = $prefix % 8;
        if ($remaining_bits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remaining_bits)) & 0xFF;
        return (ord($packed_ip[$full_bytes]) & $mask) === (ord($packed_network[$full_bytes]) & $mask);
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
               `id` int {$default_key_sign} NOT NULL auto_increment,
               `name` varchar(255) DEFAULT NULL,
               `value` varchar(255) DEFAULT NULL,
               `type` int NOT NULL DEFAULT '0',
               `comment` text,
               PRIMARY KEY (`id`),
               KEY `type` (`type`),
               KEY `value` (`value`)
               ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset}
               COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";
            $DB->doQuery($query) or throw new RuntimeException($DB->error());
        }
    }

    /**
     * uninstall
     */
    public static function uninstall(Migration $migration): void
    {
        $migration->dropTable(self::getTable());
    }
}
