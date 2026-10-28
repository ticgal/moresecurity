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

use Safe\Exceptions\SafeExceptionInterface;

use function Safe\glob;
use function Safe\json_encode;
use function Safe\parse_url;
use function Safe\preg_match;
use function Safe\preg_replace;

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
    global $CFG_GLPI;

    // Sin POST o sin credenciales no hay intento de login real: no se
    // comprueba ni se cuenta nada (evita el DoS colectivo de UC-02). Los
    // tipos y longitudes se validan antes de tocar la base de datos (MS-11).
    $login = PluginMoresecurityLimiter::cleanIdentity($_POST['login_name'] ?? null);
    if (
        ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
        || $login === null
        || !PluginMoresecurityLimiter::isPlainString($_POST['login_password'] ?? null)
        || $_POST['login_password'] === ''
        || (isset($_POST['auth']) && !PluginMoresecurityLimiter::isPlainString($_POST['auth'], 64))
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
    $ip = PluginMoresecurityLimiter::getClientIp();
    $whitelisted = $ip && PluginMoresecurityWhitelist::isWhitelisted($ip);

    if (!$whitelisted && $ip !== '') {
        // Una IP ya bloqueada se rechaza antes de evaluar el geobloqueo y sin
        // escribir nada: no hay trabajo ni filas por petición (SEV-02).
        if (PluginMoresecurityLoginip::isIpBlockActive($ip)) {
            plugin_moresecurity_deny(
                401,
                [__('Too many failed login attempts from your IP. Please try again later.', 'moresecurity')],
                $suffix
            );
        }

        // El geobloqueo es una política distinta del bloqueo por IP, pero la
        // whitelist también le vale de válvula de seguridad. Las denegaciones
        // se cuentan contra el presupuesto de la IP para que un origen
        // insistente acabe bloqueado en lugar de escribir sin límite.
        if (!PluginMoresecurityGeoip::isAllowed($ip, $login)) {
            PluginMoresecurityLoginip::countGeoDenial($ip);
            plugin_moresecurity_deny(
                403,
                [__('Login from your location is not permitted.', 'moresecurity')],
                $suffix
            );
        }
    }

    if (!$whitelisted) {
        $denied = PluginMoresecurityLogin::reserve($login, $ip);
        if ($denied === 'ip') {
            plugin_moresecurity_deny(
                401,
                [__('Too many failed login attempts from your IP. Please try again later.', 'moresecurity')],
                $suffix
            );
        } elseif ($denied !== null) {
            plugin_moresecurity_deny(
                401,
                [__('Too many failed login attempts. Please try again later', 'moresecurity')],
                $suffix
            );
        }
    }

    try {
        $success = $auth->login($login, $password, $_REQUEST["noAUTO"] ?? false, $remember, $login_auth);
    } catch (Glpi\Exception\RedirectException $e) {
        // Contraseña correcta pero pendiente de MFA (o alta de MFA): el
        // intento no fue un fallo, se libera el contador (H11).
        if (!$whitelisted && $auth->auth_succeded) {
            PluginMoresecurityLogin::clearLoginTry($login);
        }
        throw $e;
    }

    if ($success) {
        PluginMoresecurityLogin::clearLoginTry($login);
        Auth::redirectIfAuthenticated();
    } else {
        // El intento ya se contó al reservarlo; una IP en whitelist no
        // alimenta ningún contador (UC-08), pero el fallo sí queda en el
        // registro de seguridad.
        PluginMoresecurityAttemptLog::recordFailedLogin($login, $ip);
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
    $email = PluginMoresecurityLimiter::cleanEmail($_POST['email'] ?? null);
    if ($email === null) {
        plugin_moresecurity_deny(400, [__('Please enter a valid email address.', 'moresecurity')]);
    }

    $ip = PluginMoresecurityLimiter::getClientIp();
    if (!($ip && PluginMoresecurityWhitelist::isWhitelisted($ip))) {
        if (PluginMoresecurityLostpassword::reserve($email, $ip) !== null) {
            plugin_moresecurity_deny(401, [__('Too many password change attempts. Please try again later.', 'moresecurity')]);
        }
    }

    PluginMoresecurityAttemptLog::recordResetRequest($email, $ip);

    return $email;
}

/**
 * CalDAV (/caldav.php, HTTP Basic): mismas reglas que el login web. Se
 * rechaza si la IP o la cuenta están bloqueadas o la IP no está permitida; el
 * intento se reserva antes y se libera al terminar si no hubo 401.
 */
function plugin_moresecurity_enforce_caldav_gate(): void
{
    // Apache no siempre rellena PHP_AUTH_USER (sabre lee la cabecera directa).
    $user = $_SERVER['PHP_AUTH_USER'] ?? null;
    if ($user === null) {
        $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if (stripos($header, 'Basic ') === 0) {
            $decoded = base64_decode(substr($header, 6), true);
            $user    = is_string($decoded) && str_contains($decoded, ':') ? explode(':', $decoded, 2)[0] : null;
        }
    }
    $login = PluginMoresecurityLimiter::cleanIdentity($user);
    $ip    = PluginMoresecurityLimiter::getClientIp();
    if ($login === null || ($ip !== '' && PluginMoresecurityWhitelist::isWhitelisted($ip))) {
        return;
    }

    $refuse = static function (int $status): never {
        http_response_code($status);
        exit;
    };

    if ($ip !== '') {
        if (PluginMoresecurityLoginip::isIpBlockActive($ip)) {
            $refuse(429);
        }
        if (!PluginMoresecurityGeoip::isAllowed($ip, $login)) {
            PluginMoresecurityLoginip::countGeoDenial($ip);
            $refuse(403);
        }
    }

    if (PluginMoresecurityLogin::reserve($login, $ip) !== null) {
        $refuse(429);
    }

    register_shutdown_function(static function () use ($login): void {
        if (http_response_code() !== 401) {
            PluginMoresecurityLogin::clearLoginTry($login);
        }
    });
}

/**
 * Hook post_init (arranca antes de enrutar a cualquier script legacy,
 * incluido /front/login.php nativo). Cierra el bypass de UC-01.
 *
 * - Se aplica también con sesión autenticada (MS-01): cambiar de identidad
 *   por la ruta nativa no puede saltarse los presupuestos.
 * - Antes de autenticar o escribir contadores exige un token CSRF válido
 *   (MS-07). Sin token válido no se hace nada y el control CSRF nativo
 *   rechaza la petición después.
 */
function plugin_moresecurity_enforce_login_gate(): void
{
    global $CFG_GLPI;

    try {
        $path = rawurldecode((string) parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH));
        $path = preg_replace('#/+#', '/', $path);
    } catch (SafeExceptionInterface $e) {
        // URI imposible de analizar: mismo resultado que antes (ruta vacía).
        $path = '';
    }

    // CalDAV verifica contraseñas con HTTP Basic en cualquier método.
    if (preg_match('#/caldav\.php(/|$)#', $path)) {
        plugin_moresecurity_enforce_caldav_gate();
    }

    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        return;
    }

    if (isset($_POST['login_name']) || isset($_POST['login_password'])) {
        // Ningún otro script del núcleo procesa credenciales: se atiende
        // cualquier ruta, no solo las conocidas, para no dejar atajos.
        // Sin token válido en el cuerpo no se devuelve el control: el núcleo
        // aceptaría el token de cabecera y abriría sesión sin pasar por el
        // geobloqueo ni los contadores.
        if (!Session::validateCSRF($_POST)) {
            plugin_moresecurity_deny(403, [__('Invalid or expired security token. Please reload the page and try again.', 'moresecurity')]);
        }
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
            // Html::redirect() lanza RedirectException; el listener HTTP
            // normal aún no está activo en post_init, así que se envía aquí.
            $e->getResponse()->send();
            exit;
        }
    }

    if (
        isset($_POST['email'])
        && !isset($_REQUEST['password_forget_token'])
        && preg_match('#/(front/lostpassword\.php|front/initpassword\.php|plugins/moresecurity/front/lostpassword\.form\.php)(/|$)#', $path)
        && $CFG_GLPI['notifications_mailing']
        && countElementsInTable('glpi_notifications', ['itemtype' => 'User', 'event' => 'passwordforget', 'is_active' => 1])
    ) {
        // El token no se consume: si la solicitud se admite, continúa hacia
        // el controlador, cuyo control CSRF nativo lo consumirá.
        if (!Session::validateCSRF($_POST, true)) {
            return;
        }
        try {
            plugin_moresecurity_enforce_recovery();
        } catch (Glpi\Exception\RedirectException $e) {
            $e->getResponse()->send();
            exit;
        }
        $_POST['email'] = PluginMoresecurityLimiter::cleanEmail($_POST['email']);
    }
}
