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

use Glpi\Dashboard\Dashboard;
use Migration;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

/**
 * Default dashboard provider for More Security plugin.
 *
 * Provides a pre-configured "More Security" dashboard with 9 dashboard
 * cards: top attacking IPs and most targeted accounts for 24h/7d/30d in a
 * 2-column × 3-row grid, plus the 3 "top offending countries" cards side by
 * side in a row below, ready for immediate use after plugin activation.
 *
 * Grid coordinates and card_options below are taken verbatim from a manually
 * tuned reference dashboard so new installs start with the same layout and
 * styling (colors, gradients, legends, per-card row limits) that was
 * hand-picked for readability.
 */
class DashboardGrid
{
    private const DASHBOARD_KEY = 'plugin_moresecurity_board';

    /**
     * Create the "More Security" dashboard in DB if it doesn't exist yet.
     *
     * GLPI 11 has no plugin hook to seed default dashboards on an existing instance, so the
     * dashboard is created explicitly here, skipping if one with this key already exists so
     * re-running install() on update doesn't wipe user customizations.
     */
    public static function install(Migration $migration): void
    {
        $migration->displayMessage('Adding More Security dashboard');

        $dashboard = new Dashboard(self::DASHBOARD_KEY);
        if ($dashboard->load()) {
            return;
        }

        $dashboard->fields['name']     = __('More Security', 'moresecurity');
        $dashboard->fields['context']  = 'core';
        $dashboard->fields['users_id'] = 0;
        $dashboard->save(true);
        $dashboard->saveItems(self::buildDashboardItems());
    }

    /**
     * Build the grid items (dashboard cards) for the More Security dashboard.
     *
     * Arranges the 6 IP/account cards in a 2-column × 3-row layout, with the
     * 3 country cards side by side in a row below:
     * - Row 1 (y=0): Top attacking IPs (24h)        | Most targeted accounts (24h)
     * - Row 2 (y=3): Top attacking IPs (7d)          | Most targeted accounts (7d)
     * - Row 3 (y=6): Top attacking IPs (30d)         | Most targeted accounts (30d)
     * - Row 4 (y=9): Top offending countries 24h | 7d | 30d, side by side
     *
     * @return array the dashboard grid items
     */
    private static function buildDashboardItems(): array
    {
        return [
            // Row 1: 24-hour range
            [
                'gridstack_id' => 'moresecurity_top_attacking_ips_24h_22c9a067-7de1-4726-b1af-65815e581822',
                'card_id'      => 'moresecurity_top_attacking_ips_24h',
                'x'            => 0,
                'y'            => 0,
                'width'        => 13,
                'height'       => 3,
                'card_options' => [
                    'color'         => '#f4cccc',
                    'widgettype'    => 'summaryNumbers',
                    'palette'       => '',
                    'use_gradient'  => '1',
                    'point_labels'  => '1',
                    'legend'        => '1',
                    'limit'         => '5',
                ],
            ],
            [
                'gridstack_id' => 'moresecurity_most_targeted_accounts_24h_b2e01d53-27ff-45a0-a522-bbe823bf9c28',
                'card_id'      => 'moresecurity_most_targeted_accounts_24h',
                'x'            => 13,
                'y'            => 0,
                'width'        => 13,
                'height'       => 3,
                'card_options' => [
                    'color'         => '#6fa8dc',
                    'widgettype'    => 'summaryNumbers',
                    'palette'       => '',
                    'use_gradient'  => '1',
                    'point_labels'  => '1',
                    'legend'        => '1',
                    'limit'         => '5',
                ],
            ],
            // Row 2: 7-day range
            [
                'gridstack_id' => 'moresecurity_top_attacking_ips_7d_04b3768f-c4a6-422e-b66b-099a2fe8b80f',
                'card_id'      => 'moresecurity_top_attacking_ips_7d',
                'x'            => 0,
                'y'            => 3,
                'width'        => 13,
                'height'       => 3,
                'card_options' => [
                    'color'         => '#f4cccc',
                    'widgettype'    => 'summaryNumbers',
                    'palette'       => '',
                    'use_gradient'  => '1',
                    'point_labels'  => '1',
                    'legend'        => '1',
                    'limit'         => '5',
                ],
            ],
            [
                'gridstack_id' => 'moresecurity_most_targeted_accounts_7d_15dc992e-8563-4e20-bf04-72781a868038',
                'card_id'      => 'moresecurity_most_targeted_accounts_7d',
                'x'            => 13,
                'y'            => 3,
                'width'        => 13,
                'height'       => 3,
                'card_options' => [
                    'color'         => '#6fa8dc',
                    'widgettype'    => 'summaryNumbers',
                    'palette'       => '',
                    'use_gradient'  => '1',
                    'point_labels'  => '1',
                    'legend'        => '1',
                    'limit'         => '5',
                ],
            ],
            // Row 3: 30-day range
            [
                'gridstack_id' => 'moresecurity_top_attacking_ips_30d_c6a83ac4-6b67-44dc-9771-6d07e2ac4786',
                'card_id'      => 'moresecurity_top_attacking_ips_30d',
                'x'            => 0,
                'y'            => 6,
                'width'        => 13,
                'height'       => 3,
                'card_options' => [
                    'color'         => '#f4cccc',
                    'widgettype'    => 'summaryNumbers',
                    'palette'       => '',
                    'use_gradient'  => '1',
                    'point_labels'  => '1',
                    'legend'        => '1',
                    'limit'         => '5',
                ],
            ],
            [
                'gridstack_id' => 'moresecurity_most_targeted_accounts_30d_ef67671b-fd92-48c3-b991-31a2a0d0ae17',
                'card_id'      => 'moresecurity_most_targeted_accounts_30d',
                'x'            => 13,
                'y'            => 6,
                'width'        => 13,
                'height'       => 3,
                'card_options' => [
                    'color'         => '#cfe2f3',
                    'widgettype'    => 'summaryNumbers',
                    'palette'       => '',
                    'use_gradient'  => '1',
                    'point_labels'  => '1',
                    'legend'        => '1',
                    'limit'         => '5',
                ],
            ],
            // Row 4: Top offending countries, side by side.
            [
                'gridstack_id' => 'moresecurity_top_offending_countries_24h_4370cf5a-7988-4296-8f97-38d5b4a84090',
                'card_id'      => 'moresecurity_top_offending_countries_24h',
                'x'            => 0,
                'y'            => 9,
                'width'        => 9,
                'height'       => 6,
                'card_options' => [
                    'color'        => '#fff2cc',
                    'widgettype'   => 'stackedbars',
                    'palette'      => '',
                    'use_gradient' => '1',
                    'point_labels' => '1',
                    'legend'       => '1',
                    'limit'        => '5',
                ],
            ],
            [
                'gridstack_id' => 'moresecurity_top_offending_countries_7d_41f44f61-a4c4-4dea-af44-d4ea0f3ddd33',
                'card_id'      => 'moresecurity_top_offending_countries_7d',
                'x'            => 9,
                'y'            => 9,
                'width'        => 9,
                'height'       => 6,
                'card_options' => [
                    'color'        => '#d9ead3',
                    'widgettype'   => 'stackedbars',
                    'palette'      => '',
                    'use_gradient' => '1',
                    'point_labels' => '1',
                    'legend'       => '1',
                    'limit'        => '5',
                ],
            ],
            [
                'gridstack_id' => 'moresecurity_top_offending_countries_30d_c0f75912-e807-4136-8807-18f49efcb833',
                'card_id'      => 'moresecurity_top_offending_countries_30d',
                'x'            => 18,
                'y'            => 9,
                'width'        => 8,
                'height'       => 6,
                'card_options' => [
                    'color'        => '#d9d2e9',
                    'widgettype'   => 'stackedbars',
                    'palette'      => '',
                    'use_gradient' => '1',
                    'point_labels' => '1',
                    'legend'       => '1',
                    'limit'        => '5',
                ],
            ],
        ];
    }

    public static function uninstall(Migration $migration): void
    {
        $migration->displayMessage('Removing More Security dashboard');

        $dashboard = new Dashboard(self::DASHBOARD_KEY);
        if ($dashboard->load()) {
            $dashboard->delete(['key' => self::DASHBOARD_KEY], true);
        }
    }
}
