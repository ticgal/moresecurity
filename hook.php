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

use GlpiPlugin\Moresecurity\Config;
use GlpiPlugin\Moresecurity\Limiter;
use GlpiPlugin\Moresecurity\Login;
use GlpiPlugin\Moresecurity\Loginip;
use GlpiPlugin\Moresecurity\Lostpassword;
use GlpiPlugin\Moresecurity\Retention;
use GlpiPlugin\Moresecurity\Whitelist;

/**
 * Clases con install()/uninstall(), en orden de instalación.
 *
 * @return list<class-string>
 */
function plugin_moresecurity_classes(): array
{
    return [
        Config::class,
        Login::class,
        Loginip::class,
        Lostpassword::class,
        Retention::class,
        Whitelist::class,
    ];
}

function plugin_moresecurity_install()
{
    /** @var \DBmysql $DB */
    global $DB;

    $migration = new Migration(PLUGIN_MORESECURITY_VERSION);

    // 3.0.0: las clases pasan a GlpiPlugin\Moresecurity\*; los itemtype
    // guardados con el nombre legacy (acción automática, preferencias de
    // visualización, búsquedas guardadas, historial) se renombran antes de
    // instalar, para que CronTask::register() no duplique la tarea.
    foreach (plugin_moresecurity_classes() as $classname) {
        $legacy = 'PluginMoresecurity' . substr($classname, strrpos($classname, '\\') + 1);
        // Si ya hay filas con el FQCN (upgrade interrumpido), las legacy
        // sobran y romperían los índices únicos al renombrarlas.
        foreach (['glpi_crontasks', 'glpi_displaypreferences'] as $table) {
            if (countElementsInTable($table, ['itemtype' => $classname]) > 0) {
                $DB->delete($table, ['itemtype' => $legacy]);
            }
        }
        $migration->renameItemtype($legacy, $classname, false);
    }

    foreach (plugin_moresecurity_classes() as $classname) {
        $classname::install($migration);
    }
    $migration->executeMigration();

    return true;
}

function plugin_moresecurity_uninstall()
{
    $migration = new Migration(PLUGIN_MORESECURITY_VERSION);

    foreach (plugin_moresecurity_classes() as $classname) {
        $classname::uninstall($migration);
    }
    $migration->executeMigration();

    return true;
}

function plugin_moresecurity_getDropdown(): array
{
    $plugin = new Plugin();

    if ($plugin->isActivated('moresecurity')) {
        return [
            Whitelist::class => Whitelist::getTypeName(),
        ];
    }

    return [];
}

function plugin_moresecurity_displayLogin()
{
    /** @var array $CFG_GLPI */
    global $CFG_GLPI;

    $root = $CFG_GLPI['root_doc'];
    $url      = json_encode($root . '/plugins/moresecurity/front/login.form.php', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    $urllost  = json_encode($root . '/plugins/moresecurity/front/lostpassword.form.php', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

    $script = <<<JAVASCRIPT
    $(document).ready(function() {
        $('div.card-body form').attr('action', {$url});
        $("div.card-body form a[href$='?lostpassword=1']").attr('href', {$urllost});
    });
JAVASCRIPT;

    echo Html::scriptBlock($script);
}

/**
 * Muestra la página de error genérica de login/recuperación y termina.
 */
function plugin_moresecurity_deny(int $status, array $errors, string $suffix = ''): never
{
    /** @var array $CFG_GLPI */
    global $CFG_GLPI;

    http_response_code($status);
    Glpi\Application\View\TemplateRenderer::getInstance()->display('pages/login_error.html.twig', [
        'errors'    => $errors,
        'login_url' => $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1' . $suffix,
    ]);
    exit;
}

/**
 * Lógica de login compartida entre front/login.form.php y el hook post_init
 * (UC-01). Siempre termina con exit, nunca return.
 *
 * El presupuesto de intentos se RESERVA antes de autenticar (MS-06) y un
 * login correcto lo libera; así solicitudes simultáneas no pueden superar
 * todas a la vez una comprobación previa.
 */
function plugin_moresecurity_process_login(): void
{
    /** @var array $CFG_GLPI */
    global $CFG_GLPI;

    // Sin POST o sin credenciales no hay intento de login real: no se
    // comprueba ni se cuenta nada (evita el DoS colectivo de UC-02). Los
    // tipos y longitudes se validan antes de tocar la base de datos (MS-11).
    $login = Limiter::cleanIdentity($_POST['login_name'] ?? null);
    if (
        ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
        || $login === null
        || !Limiter::isPlainString($_POST['login_password'] ?? null)
        || $_POST['login_password'] === ''
        || (isset($_POST['auth']) && !Limiter::isPlainString($_POST['auth'], 64))
    ) {
        plugin_moresecurity_deny(400, [__('Incorrect username or password')]);
    }

    $password   = $_POST['login_password'];
    $login_auth = $_POST['auth'] ?? '';
    $remember   = isset($_POST['login_remember']) && $CFG_GLPI["login_remember_time"];

    $REDIRECT = "";
    foreach ([$_POST['redirect'] ?? null, $_GET['redirect'] ?? null] as $candidate) {
        if (is_string($candidate) && $candidate !== '' && strlen($candidate) <= 2048) {
            $REDIRECT = "?redirect=" . rawurlencode($candidate);
            break;
        }
    }
    $suffix = str_replace("?", "&", $REDIRECT);

    $auth = new Auth();
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $whitelisted = $ip && Whitelist::isWhitelisted($ip);

    if (!$whitelisted) {
        $denied = Login::reserve($login, $ip);
        if ($denied === 'ip') {
            plugin_moresecurity_deny(
                401,
                [__('Too many failed login attempts from your IP. Please try again later.', 'moresecurity')],
                $suffix,
            );
        } elseif ($denied !== null) {
            plugin_moresecurity_deny(
                401,
                [__('Too many failed login attempts. Please try again later', 'moresecurity')],
                $suffix,
            );
        }
    }

    try {
        $success = $auth->login($login, $password, $_REQUEST["noAUTO"] ?? false, $remember, $login_auth);
    } catch (Glpi\Exception\RedirectException $e) {
        // Contraseña correcta pero pendiente de MFA (o alta de MFA): el
        // intento no fue un fallo, se libera el contador (H11).
        if (!$whitelisted && $auth->auth_succeded) {
            Login::clearLoginTry($login);
        }
        throw $e;
    }

    if ($success) {
        Login::clearLoginTry($login);
        Auth::redirectIfAuthenticated();
    } else {
        // El intento ya se contó al reservarlo; una IP en whitelist no
        // alimenta ningún contador (UC-08).
        plugin_moresecurity_deny(401, $auth->getErrors(), $suffix);
    }
}

/**
 * Recuperación de contraseña (MS-04): misma política en la ruta nativa y en
 * la del plugin, sin depender de reescribir el DOM. Devuelve el email
 * normalizado si la solicitud puede continuar; si no, responde y termina.
 */
function plugin_moresecurity_enforce_recovery(): string
{
    $email = Limiter::cleanEmail($_POST['email'] ?? null);
    if ($email === null) {
        plugin_moresecurity_deny(400, [__('Please enter a valid email address.', 'moresecurity')]);
    }

    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!($ip && Whitelist::isWhitelisted($ip))) {
        if (Lostpassword::reserve($email, $ip) !== null) {
            plugin_moresecurity_deny(401, [__('Too many password change attempts. Please try again later.', 'moresecurity')]);
        }
    }

    return $email;
}

/**
 * Misma regla que Glpi\Kernel\Listener\ControllerListener\CheckCsrfListener,
 * que en GLPI 12 sustituye a los tokens CSRF. Hace falta replicarla porque
 * post_init se ejecuta durante el arranque del kernel, antes que ese
 * listener, y Session::validateCSRF() ya siempre devuelve true.
 *
 * Una petición sin Sec-Fetch-Site ni Origin no viene de un navegador y no
 * está sujeta a CSRF (sí al presupuesto de intentos).
 */
function plugin_moresecurity_is_csrf_safe(): bool
{
    $sec_fetch_site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
    if (is_string($sec_fetch_site)) {
        return in_array($sec_fetch_site, ['same-origin', 'none'], true);
    }

    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    $host   = $_SERVER['HTTP_HOST'] ?? null;
    if (is_string($origin) && is_string($host)) {
        $origin_host = parse_url($origin, PHP_URL_HOST);
        if (!is_string($origin_host) || $origin_host === '') {
            return false;
        }
        $origin_port = parse_url($origin, PHP_URL_PORT);

        return (is_int($origin_port) ? "$origin_host:$origin_port" : $origin_host) === $host;
    }

    return true;
}

/**
 * Hook post_init (arranca antes de enrutar a cualquier script legacy,
 * incluido /front/login.php nativo). Cierra el bypass de UC-01.
 *
 * - Se aplica también con sesión autenticada (MS-01): cambiar de identidad
 *   por la ruta nativa no puede saltarse los presupuestos.
 * - Antes de autenticar o escribir contadores exige que la petición no
 *   sea cross-site (MS-07). Si lo es no se hace nada y el control CSRF
 *   nativo la rechaza después.
 */
function plugin_moresecurity_enforce_login_gate(): void
{
    /** @var array $CFG_GLPI */
    global $CFG_GLPI;

    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        return;
    }

    $path = rawurldecode((string) parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH));
    $path = preg_replace('#/+#', '/', $path);

    if (isset($_POST['login_name']) || isset($_POST['login_password'])) {
        // Ningún otro script del núcleo procesa credenciales: se atiende
        // cualquier ruta, no solo las conocidas, para no dejar atajos.
        if (!plugin_moresecurity_is_csrf_safe()) {
            return;
        }
        try {
            if (!isset($_SESSION["glpicookietest"]) || ($_SESSION["glpicookietest"] != 'testcookie')) {
                if (!Session::canWriteSessionFiles()) {
                    Html::redirect($CFG_GLPI['root_doc'] . "/index.php?error=2");
                } else {
                    Html::redirect($CFG_GLPI['root_doc'] . "/index.php?error=1");
                }
            }

            plugin_moresecurity_process_login();
        } catch (Glpi\Exception\RedirectException $e) {
            // Html::redirect() lanza RedirectException; el listener HTTP
            // normal aún no está activo en post_init, así que se envía aquí.
            $e->getResponse()->send();
            exit;
        }
    }

    if (
        isset($_POST['email'])
        && !isset($_REQUEST['password_forget_token'])
        && preg_match('#/(front/lostpassword\.php|plugins/moresecurity/front/lostpassword\.form\.php)(/|$)#', $path)
        && $CFG_GLPI['notifications_mailing']
        && countElementsInTable('glpi_notifications', ['itemtype' => 'User', 'event' => 'passwordforget', 'is_active' => 1])
    ) {
        if (!plugin_moresecurity_is_csrf_safe()) {
            return;
        }
        try {
            plugin_moresecurity_enforce_recovery();
        } catch (Glpi\Exception\RedirectException $e) {
            $e->getResponse()->send();
            exit;
        }
        $_POST['email'] = Limiter::cleanEmail($_POST['email']);
    }
}
