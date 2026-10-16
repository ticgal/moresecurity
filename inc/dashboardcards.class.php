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

use function Safe\strtotime;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

/**
 * Dashboard cards for Central: attack sources ("Top Attacking IPs") and
 * attack targets ("Most Targeted Accounts"), each split into three
 * fixed time-range cards (24h / 7 days / 30 days).
 *
 * Kept as two clearly distinct metrics on purpose: IPs are offenders
 * (actionable, banning them is safe), while identifiers are victims
 * (banning them would lock out the very users being attacked).
 */
class PluginMoresecurityDashboardCards
{
    /** @var array<string,int> time-range slug => window size in hours */
    private const RANGES = [
        '24h' => 24,
        '7d'  => 24 * 7,
        '30d' => 24 * 30,
    ];

    /** @var array<string,string> time-range slug => human label suffix */
    private const RANGE_LABELS = [
        '24h' => 'last 24 hours',
        '7d'  => 'last 7 days',
        '30d' => 'last 30 days',
    ];

    public static function dashboardCards(?array $cards = null): array
    {
        $cards ??= [];

        // ajax/dashboard.php solo exige poder ver un dashboard: aplicar aquí el
        // derecho del Security log (SEV-01). Sin sesión (dashboard embebido con
        // token) no se filtra, lo protege el token.
        if (Session::getLoginUserID() && !Session::haveRight(PluginMoresecurityAttemptLog::$rightname, READ)) {
            return $cards;
        }

        foreach (self::RANGES as $slug => $hours) {
            $cards["moresecurity_top_attacking_ips_{$slug}"] = [
                'widgettype' => ['pie', 'donut', 'bar', 'hbar', 'multipleNumber', 'summaryNumbers'],
                'itemtype'   => PluginMoresecurityAttemptLog::class,
                'group'      => __s('More Security'),
                'label'      => sprintf(
                    __s('Top attacking IPs (%s)'),
                    __s(self::RANGE_LABELS[$slug])
                ),
                'provider'   => self::class . "::provideTopAttackingIps{$slug}",
                'cache'      => false,
            ];

            $cards["moresecurity_most_targeted_accounts_{$slug}"] = [
                'widgettype' => ['pie', 'donut', 'bar', 'hbar', 'multipleNumber', 'summaryNumbers'],
                'itemtype'   => PluginMoresecurityAttemptLog::class,
                'group'      => __s('More Security'),
                'label'      => sprintf(
                    __s('Most targeted accounts (%s)'),
                    __s(self::RANGE_LABELS[$slug])
                ),
                'provider'   => self::class . "::provideMostTargetedAccounts{$slug}",
                'cache'      => false,
            ];

            $cards["moresecurity_top_offending_countries_{$slug}"] = [
                'widgettype' => ['stackedbars', 'stackedHBars', 'bars', 'hBars'],
                'itemtype'   => PluginMoresecurityAttemptLog::class,
                'group'      => __s('More Security'),
                'label'      => sprintf(
                    __s('Top offending countries (%s)'),
                    __s(self::RANGE_LABELS[$slug])
                ),
                'provider'   => self::class . "::provideTopOffendingCountries{$slug}",
                'cache'      => false,
            ];
        }

        return $cards;
    }

    public static function provideTopAttackingIps24h(): array
    {
        return self::buildIpData(self::RANGES['24h'], '24h');
    }

    public static function provideTopAttackingIps7d(): array
    {
        return self::buildIpData(self::RANGES['7d'], '7d');
    }

    public static function provideTopAttackingIps30d(): array
    {
        return self::buildIpData(self::RANGES['30d'], '30d');
    }

    public static function provideMostTargetedAccounts24h(): array
    {
        return self::buildAccountData(self::RANGES['24h'], '24h');
    }

    public static function provideMostTargetedAccounts7d(): array
    {
        return self::buildAccountData(self::RANGES['7d'], '7d');
    }

    public static function provideMostTargetedAccounts30d(): array
    {
        return self::buildAccountData(self::RANGES['30d'], '30d');
    }

    public static function provideTopOffendingCountries24h(): array
    {
        return self::buildCountryData(self::RANGES['24h'], '24h');
    }

    public static function provideTopOffendingCountries7d(): array
    {
        return self::buildCountryData(self::RANGES['7d'], '7d');
    }

    public static function provideTopOffendingCountries30d(): array
    {
        return self::buildCountryData(self::RANGES['30d'], '30d');
    }

    private static function buildIpData(int $hours, string $rangeSlug): array
    {
        $rows  = PluginMoresecurityAttemptLog::getTopAttackingIps($hours);
        $label = sprintf(__('Top attacking IPs (%s)'), __(self::RANGE_LABELS[$rangeSlug]));

        if (empty($rows)) {
            return ['data' => ['nodata' => true], 'label' => $label, 'alt' => $label];
        }

        $data = [];
        foreach ($rows as $row) {
            $data[] = [
                'number' => (int) $row['total'],
                'label'  => $row['ip'],
                'url'    => self::buildDrilldownUrl($hours, 'ip', $row['ip'], [
                    PluginMoresecurityAttemptLog::EVENT_LOGIN_IP,
                    PluginMoresecurityAttemptLog::EVENT_RESET_IP,
                ]),
            ];
        }

        return [
            'data'  => $data,
            'label' => $label,
            'alt'   => $label,
        ];
    }

    private static function buildAccountData(int $hours, string $rangeSlug): array
    {
        $rows  = PluginMoresecurityAttemptLog::getMostTargetedAccounts($hours);
        $label = sprintf(__('Most targeted accounts (%s)'), __(self::RANGE_LABELS[$rangeSlug]));

        if (empty($rows)) {
            return ['data' => ['nodata' => true], 'label' => $label, 'alt' => $label];
        }

        $data = [];
        foreach ($rows as $row) {
            $data[] = [
                'number' => (int) $row['total'],
                // El identificador lo escribe un anónimo (login_name): sin marcado en la etiqueta del gráfico.
                'label'  => str_replace(['<', '>', '&', '"', "'"], '', $row['identifier']),
                'url'    => self::buildDrilldownUrl($hours, 'identifier', $row['identifier'], [
                    PluginMoresecurityAttemptLog::EVENT_LOGIN,
                    PluginMoresecurityAttemptLog::EVENT_RESET_EMAIL,
                ]),
            ];
        }

        return [
            'data'  => $data,
            'label' => $label,
            'alt'   => $label,
        ];
    }

    private static function buildCountryData(int $hours, string $rangeSlug): array
    {
        $breakdown = PluginMoresecurityAttemptLog::getTopCountriesByType($hours);

        $label = sprintf(__('Top offending countries (%s)'), __(self::RANGE_LABELS[$rangeSlug]));

        if (empty($breakdown['countries'])) {
            // Los widgets de barras múltiples leen data.labels y data.series
            // sin comprobar nodata: sin ellas, "Undefined array key series". El
            // gráfico borra el aviso nativo, así que se dibuja una única
            // categoría vacía con el texto como etiqueta del eje.
            return [
                'data'  => [
                    'labels' => [__('No data found')],
                    'series' => [['name' => ' ', 'data' => [['value' => null, 'url' => '']]]],
                ],
                'label' => $label,
                'alt'   => $label,
            ];
        }

        $type_labels = PluginMoresecurityAttemptLog::getTypeLabels();

        $labels = [];
        foreach (array_keys($breakdown['countries']) as $country) {
            $labels[] = PluginMoresecurityGeoip::getCountryDisplayName($country);
        }

        $series = [];
        foreach ($breakdown['events'] as $event) {
            $series_data = [];
            foreach ($breakdown['countries'] as $country => $counts) {
                // Absent (country, event) combination: a genuine gap, not a
                // zero — fill with null so the chart renders no segment for
                // it instead of a real (if invisible) zero-height one.
                $count = $counts[$event] ?? null;
                $series_data[] = [
                    'value' => $count,
                    'url'   => self::buildCountryDrilldownUrl($hours, $country, $event),
                ];
            }
            $series[] = [
                'name' => $type_labels[$event] ?? $event,
                'data' => $series_data,
            ];
        }

        return [
            'data'  => ['labels' => $labels, 'series' => $series],
            'label' => $label,
            'alt'   => $label,
        ];
    }

    /**
     * Drill-down for a country/event data point: opens the Security Log
     * filtered to that country and event type within the card's own time
     * window — same pattern as buildDrilldownUrl(), but keyed on the
     * country search option (id 20) instead of ip/identifier, and a single
     * event per point (each series is already one event type) instead of
     * an OR pair.
     */
    private static function buildCountryDrilldownUrl(int $hours, string $country_code, string $event): string
    {
        // Reproduce the provider's own >-bound window with one extra hour
        // of slack so the drill-down search's inclusive comparison returns
        // exactly the same rows the card's own query counted.
        $since = date('Y-m-d H:i:s', strtotime('-' . ($hours + 1) . ' hours'));

        $criteria = [
            'criteria' => [
                [
                    'link'       => 'AND',
                    'field'      => 20, // country
                    'searchtype' => 'equals',
                    'value'      => $country_code,
                ],
                [
                    'link'       => 'AND',
                    'field'      => 10, // event
                    'searchtype' => 'equals',
                    'value'      => $event,
                ],
                [
                    'link'       => 'AND',
                    'field'      => 14, // date
                    'searchtype' => 'morethan',
                    'value'      => $since,
                ],
            ],
        ];

        return PluginMoresecurityAttemptLog::getSearchURL() . '?' . Toolbox::append_params($criteria);
    }

    /**
     * @param string[] $events
     */
    private static function buildDrilldownUrl(int $hours, string $field, string $value, array $events): string
    {
        // Reproduce the provider's own >-bound window with one extra hour
        // of slack so the drill-down search's inclusive comparison returns
        // exactly the same rows the card's own query counted.
        $since = date('Y-m-d H:i:s', strtotime('-' . ($hours + 1) . ' hours'));

        // The event OR must be its own parenthesized group, otherwise GLPI's
        // search criteria chain it flat with the surrounding ANDs and the OR
        // escapes the intended scope (matches every row of the first event,
        // regardless of ip/date, instead of just the two events for this
        // specific ip/identifier and window).
        //
        // Drills down into the granular attempt log (PluginMoresecurityAttemptLog),
        // not the counter table — the cards themselves are now sourced from the
        // log (see getTopAttackingIps()/getMostTargetedAccounts()), so the
        // drill-down has to land on the same data or the numbers won't match
        // what the user clicked through from. Field ids 10 (event)/11
        // (identifier)/12 (ip)/14 (date) happen to be identical between the two
        // itemtypes' search options.
        $criteria = [
            'criteria' => [
                [
                    'link'     => 'AND',
                    'criteria' => [
                        [
                            'link'       => 'AND',
                            'field'      => 10, // event
                            'searchtype' => 'equals',
                            'value'      => $events[0],
                        ],
                        [
                            'link'       => 'OR',
                            'field'      => 10, // event
                            'searchtype' => 'equals',
                            'value'      => $events[1],
                        ],
                    ],
                ],
                [
                    'link'       => 'AND',
                    'field'      => $field === 'ip' ? 12 : 11,
                    'searchtype' => 'equals',
                    'value'      => $value,
                ],
                [
                    'link'       => 'AND',
                    'field'      => 14, // date
                    'searchtype' => 'morethan',
                    'value'      => $since,
                ],
            ],
        ];

        return PluginMoresecurityAttemptLog::getSearchURL() . '?' . Toolbox::append_params($criteria);
    }
}
