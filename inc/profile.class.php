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
use Glpi\DBAL\QueryExpression;

use function Safe\ob_get_clean;
use function Safe\ob_start;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

class PluginMoresecurityProfile extends Profile
{
    public static $rightname = 'profile';

    public static function getTypeName($nb = 0): string
    {
        return 'More Security';
    }

    public static function getIcon(): string
    {
        return 'ti ti-shield-plus';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): string|array
    {
        if ($item::getType() === Profile::getType()) {
            return self::createTabEntry(self::getTypeName(1));
        }

        return '';
    }

    /**
     * @return array
     */
    public function getAllRights(): array
    {
        return [
            [
                'rights'   => [READ => __('Read')],
                'label'    => __('Security log', 'moresecurity'),
                'itemtype' => PluginMoresecurityAttemptLog::class,
                'field'    => PluginMoresecurityAttemptLog::$rightname,
            ],
        ];
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
    {
        if ($item->getType() === Profile::getType()) {
            /** @var Profile $item */
            self::displayProfileForm($item);
            return true;
        }

        return false;
    }

    public static function displayProfileForm(Profile $profile): void
    {
        // La matriz de derechos la genera el núcleo con echo directo: se captura
        // para pintarla dentro de la plantilla y mantener el orden de salida.
        ob_start();
        $profile->displayRightsChoiceMatrix(
            (new self())->getAllRights(),
            ['canedit' => Session::haveRight(self::$rightname, UPDATE), 'title' => 'More Security']
        );
        $matrix = ob_get_clean();

        TemplateRenderer::getInstance()->display('@moresecurity/forms/profile.html.twig', [
            'can_edit'   => Session::haveRight(self::$rightname, UPDATE),
            'form_url'   => $profile::getFormURL(),
            'profile_id' => $profile->getID(),
            'matrix'     => $matrix,
        ]);
    }

    public static function install(Migration $migration): void
    {
        $migration->displayMessage('Adding More Security profile rights');

        global $DB;

        $rights = [];
        foreach ([PluginMoresecurityAttemptLog::$rightname] as $rightname) {
            $exists = $DB->request([
                'FROM'  => ProfileRight::getTable(),
                'WHERE' => ['name' => $rightname],
                'LIMIT' => 1,
            ])->count() > 0;

            if (!$exists) {
                $rights[] = $rightname;
            }
        }

        if (!empty($rights)) {
            ProfileRight::addProfileRights($rights);

            // Los derechos nuevos nacen a 0 en todos los perfiles: se concede
            // lectura a los que ya pueden configurar GLPI, que son quienes
            // administran este plugin.
            $config_profiles = array_column(iterator_to_array($DB->request([
                'SELECT' => ['profiles_id'],
                'FROM'   => ProfileRight::getTable(),
                'WHERE'  => ['name' => 'config', new QueryExpression('(`rights` & ' . (int) UPDATE . ') > 0')],
            ])), 'profiles_id');

            if ($config_profiles !== []) {
                $DB->update(
                    ProfileRight::getTable(),
                    ['rights' => READ],
                    ['name' => $rights, 'profiles_id' => $config_profiles, 'rights' => 0]
                );
            }
        }
    }

    public static function uninstall(Migration $migration): void
    {
        $migration->displayMessage('Removing More Security profile rights');
        ProfileRight::deleteProfileRights([PluginMoresecurityAttemptLog::$rightname]);
    }
}
