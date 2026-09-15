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

function plugin_moresecurity_install()
{
	$migration = new Migration(PLUGIN_MORESECURITY_VERSION);

	foreach (glob(dirname(__FILE__) . '/inc/*') as $filepath) {
		if (preg_match("/inc.(.+)\.class.php/", $filepath, $matches)) {
			$classname = 'PluginMoresecurity' . ucfirst($matches[1]);
			include_once($filepath);
			if (method_exists($classname, 'install')) {
				$classname::install($migration);
			}
		}
	}
	$migration->executeMigration();

	return true;
}

function plugin_moresecurity_uninstall()
{
	$migration = new Migration(PLUGIN_MORESECURITY_VERSION);

	foreach (glob(dirname(__FILE__) . '/inc/*') as $filepath) {
		if (preg_match("/inc.(.+)\.class.php/", $filepath, $matches)) {
			$classname = 'PluginMoresecurity' . ucfirst($matches[1]);
			include_once($filepath);
			if (method_exists($classname, 'uninstall')) {
				$classname::uninstall($migration);
			}
		}
	}
	$migration->executeMigration();

	return true;
}

function plugin_moresecurity_getDropdown(): array
{
	$plugin = new Plugin();

	if ($plugin->isActivated('moresecurity')) {
		include_once dirname(__FILE__) . '/inc/whitelist.class.php';
		return [
			PluginMoresecurityWhitelist::class => PluginMoresecurityWhitelist::getTypeName(),
		];
	}

	return [];
}

function plugin_moresecurity_displayLogin()
{
	global $CFG_GLPI;

	$root = $CFG_GLPI['root_doc'];
	$url      = $root . '/plugins/moresecurity/front/login.form.php';
	$urllost  = $root . '/plugins/moresecurity/front/lostpassword.form.php';

	$url_escaped     = htmlescape($url);
	$urllost_escaped = htmlescape($urllost);

	$script = <<<JAVASCRIPT
    $(document).ready(function() {
        $('div.card-body form').attr('action', '{$url_escaped}');
        $("div.card-body form a[href$='?lostpassword=1']").attr('href', '{$urllost_escaped}');
    });
JAVASCRIPT;

	echo Html::scriptBlock($script);
}

/**
 * Lógica de login compartida entre front/login.form.php y el hook post_init
 * (UC-01). Siempre termina con exit, nunca return.
 */
function plugin_moresecurity_process_login(): void
{
	global $CFG_GLPI;

	// Sin POST o sin credenciales no hay intento de login real: no se
	// comprueba ni se cuenta nada (evita el DoS colectivo de UC-02).
	if (
		($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
		|| !isset($_POST['login_name'], $_POST['login_password'])
		|| $_POST['login_name'] === ''
		|| $_POST['login_password'] === ''
	) {
		http_response_code(400);
		Glpi\Application\View\TemplateRenderer::getInstance()->display('pages/login_error.html.twig', [
			'errors'    => [__('Incorrect username or password')],
			'login_url' => $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1',
		]);
		exit;
	}

	// trim() como hace el propio núcleo antes de autenticar: si no se
	// normaliza aquí, "tech" y " tech" son dos identidades distintas para
	// el contador (UC-09), aunque para GLPI sean la misma cuenta.
	$login      = trim($_POST['login_name'] ?? '');
	$password   = $_POST['login_password'] ?? '';
	$login_auth = $_POST['auth'] ?? '';
	$remember   = isset($_POST['login_remember']) && $CFG_GLPI["login_remember_time"];

	$REDIRECT = "";
	if (!empty($_POST['redirect'])) {
		$REDIRECT = "?redirect=" . rawurlencode($_POST['redirect']);
	} elseif (!empty($_GET['redirect'])) {
		$REDIRECT = "?redirect=" . rawurlencode($_GET['redirect']);
	}

	$auth = new Auth();
	$ip = $_SERVER['REMOTE_ADDR'] ?? '';
	$whitelisted = $ip && PluginMoresecurityWhitelist::isWhitelisted($ip);

	if (!$whitelisted) {
		if ($ip && !PluginMoresecurityLoginip::checkIp($ip)) {
			http_response_code(401);
			Glpi\Application\View\TemplateRenderer::getInstance()->display('pages/login_error.html.twig', [
				'errors'    => [__('Too many failed login attempts from your IP. Please try again later.', 'moresecurity')],
				'login_url' => $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1' . str_replace("?", "&", $REDIRECT),
			]);
			exit;
		}

		if (!PluginMoresecurityLogin::checkLogin($login)) {
			http_response_code(401);
			Glpi\Application\View\TemplateRenderer::getInstance()->display('pages/login_error.html.twig', [
				'errors'    => [__('Too many failed login attempts. Please try again later', 'moresecurity')],
				'login_url' => $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1' . str_replace("?", "&", $REDIRECT),
			]);
			exit;
		}
	}

	if ($auth->login($login, $password, $_REQUEST["noAUTO"] ?? false, $remember, $login_auth)) {
		PluginMoresecurityLogin::clearLoginTry($login);
		Auth::redirectIfAuthenticated();
	} else {
		// Una IP en whitelist no debe alimentar el contador (UC-08): si no
		// se comprueba el bloqueo para esa IP, tampoco debe contarse, o se
		// convierte en un arma de bloqueo de cuenta / trampa de auto-bloqueo.
		if (!$whitelisted) {
			PluginMoresecurityLogin::addLoginTry($login);
		}
		http_response_code(401);
		Glpi\Application\View\TemplateRenderer::getInstance()->display('pages/login_error.html.twig', [
			'errors'    => $auth->getErrors(),
			'login_url' => $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1' . str_replace("?", "&", $REDIRECT),
		]);
		exit;
	}
}

/**
 * Hook post_init (arranca antes de enrutar a cualquier script legacy,
 * incluido /front/login.php nativo). Cierra el bypass de UC-01.
 */
function plugin_moresecurity_enforce_login_gate(): void
{
	global $CFG_GLPI;

	if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !isset($_POST['login_name'])) {
		return;
	}

	$self = $_SERVER['SCRIPT_NAME'] ?? ($_SERVER['PHP_SELF'] ?? '');
	if (str_contains($self, '/plugins/moresecurity/front/login.form.php')) {
		return;
	}

	if (Session::getLoginUserID()) {
		return;
	}

	// A esta altura del arranque (post_init, antes de enrutar la petición),
	// Html::redirect() lanza Glpi\Exception\RedirectException para que el
	// listener HTTP normal la convierta en respuesta; ese listener aún no
	// está activo, así que hay que enviarla nosotros mismos o se traduce
	// en un 500 (comprobado en vivo).
	try {
		if (!isset($_SESSION["glpicookietest"]) || ($_SESSION["glpicookietest"] != 'testcookie')) {
			if (!is_writable(GLPI_SESSION_DIR)) {
				Html::redirect($CFG_GLPI['root_doc'] . "/index.php?error=2");
			} else {
				Html::redirect($CFG_GLPI['root_doc'] . "/index.php?error=1");
			}
		}

		plugin_moresecurity_process_login();
	} catch (Glpi\Exception\RedirectException $e) {
		$e->getResponse()->send();
		exit;
	}
}
