<?php
/*
 -------------------------------------------------------------------------
 More Security plugin for GLPI
 Copyright (C) 2026 by the TICGAL Team.
 https://www.tic.gal
 -------------------------------------------------------------------------
 ...
 ----------------------------------------------------------------------
*/

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

class PluginMoresecurityWhitelist extends CommonDropdown
{
    public $dohistory = true;

    // Exención de un control de seguridad global: requiere el mismo
    // derecho que la config del plugin, no el genérico 'dropdown' (UC-05).
    public static $rightname = 'config';

    public $can_be_translated = false;

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
                    ERROR
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
    private static function normalizeIpOrCidr(string $value): ?string
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }

        if (str_contains($value, '/')) {
            [$address, $prefix] = explode('/', $value, 2);
            $packed = @inet_pton(trim($address));
            if ($packed === false || !ctype_digit($prefix)) {
                return null;
            }

            $prefix = (int) $prefix;
            if ($prefix < 0 || $prefix > strlen($packed) * 8) {
                return null;
            }

            return inet_ntop($packed) . '/' . $prefix;
        }

        $packed = @inet_pton($value);
        if ($packed === false) {
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
        $packed_ip = @inet_pton(trim($ip));
        if ($packed_ip === false) {
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
            $packed_entry = @inet_pton($entry_value);
            return $packed_entry !== false && $packed_entry === $packed_ip;
        }

        [$network, $prefix] = explode('/', $entry_value, 2);
        $packed_network = @inet_pton($network);
        if ($packed_network === false || !ctype_digit($prefix)) {
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
            $DB->doQuery($query) or die($DB->error());
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
