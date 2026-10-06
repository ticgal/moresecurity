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

use Glpi\Exception\Http\NotFoundHttpException;
use GlpiPlugin\Moresecurity\Config;

/** @var array $CFG_GLPI */
global $CFG_GLPI;

$plugin = new Plugin();
if (!$plugin->isInstalled('moresecurity') || !$plugin->isActivated('moresecurity')) {
    throw new NotFoundHttpException();
}

Session::checkRight('config', UPDATE);
Config::checkReAuthenticationOrRedirect();

$config = new Config();
if (isset($_POST["update"])) {
    $config->check($_POST['id'], UPDATE);
    $config->update($_POST);
    Html::back();
}

if (isset($_POST['unblock'])) {
    // Derecho `config` UPDATE comprobado arriba; el CSRF lo valida el núcleo.
    if (Config::unblock($_POST['unblock_type'] ?? null, $_POST['unblock_value'] ?? null)) {
        Session::addMessageAfterRedirect(__('Unblocked successfully', 'moresecurity'));
    } else {
        Session::addMessageAfterRedirect(__('Invalid unblock request', 'moresecurity'), false, ERROR);
    }
    Html::back();
}

$redirect = $CFG_GLPI["root_doc"] . "/front/config.form.php";
$redirect .= "?forcetab=" . urlencode(Config::class . '$1');
Html::redirect($redirect);
