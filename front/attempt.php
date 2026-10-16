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
use Glpi\Exception\Http\NotFoundHttpException;

$plugin = new Plugin();
if (!$plugin->isInstalled('moresecurity') || !$plugin->isActivated('moresecurity')) {
    throw new NotFoundHttpException();
}

Session::checkRight(PluginMoresecurityAttemptLog::$rightname, READ);

Html::header(
    PluginMoresecurityAttemptLog::getTypeName(Session::getPluralNumber()),
    $_SERVER['PHP_SELF'],
    'admin',
    PluginMoresecurityAttemptLog::class
);

// Two separate front files, not a `?view=` query param: GLPI's Search class
// rebuilds its own sort/filter/pagination links from itemtype-specific
// params only, dropping any unrecognized query string (like a `view` param)
// on the very first interaction — so the tab state has to live in the URL
// path instead.
TemplateRenderer::getInstance()->display('@moresecurity/attempt_tabs.html.twig', [
    'active_view' => 'log',
]);

Search::show(PluginMoresecurityAttemptLog::class);

Html::footer();
