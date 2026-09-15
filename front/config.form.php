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
global $CFG_GLPI;

use Glpi\Exception\Http\NotFoundHttpException;

$plugin = new Plugin();
if (!$plugin->isInstalled('moresecurity') || !$plugin->isActivated('moresecurity')) {
    throw new NotFoundHttpException();
}

Session::checkRight('config', UPDATE);

$config = new PluginMoresecurityConfig();
if (isset($_POST["update"])) {
    $config->check($_POST['id'], UPDATE);
    $config->update($_POST);
    Html::back();
}

$redirect = $CFG_GLPI["root_doc"] . "/front/config.form.php";
$redirect .= "?forcetab=" . urlencode('PluginMoresecurityConfig$1');
Html::redirect($redirect);
