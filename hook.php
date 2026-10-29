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

use GlpiPlugin\Moresecurity\AttemptLog;
use GlpiPlugin\Moresecurity\Config;
use GlpiPlugin\Moresecurity\DashboardCards;
use GlpiPlugin\Moresecurity\DashboardGrid;
use GlpiPlugin\Moresecurity\Geoip;
use GlpiPlugin\Moresecurity\Limiter;
use GlpiPlugin\Moresecurity\Login;
use GlpiPlugin\Moresecurity\Loginip;
use GlpiPlugin\Moresecurity\Lostpassword;
use GlpiPlugin\Moresecurity\Profile;
use GlpiPlugin\Moresecurity\Retention;
use GlpiPlugin\Moresecurity\Whitelist;
use Safe\Exceptions\SafeExceptionInterface;

use function Safe\file_get_contents;
use function Safe\json_decode;
use function Safe\json_encode;
use function Safe\parse_url;
use function Safe\preg_match;
use function Safe\preg_replace;

/**
 * Clases del plugin que tienen install()/uninstall(), en orden de instalación.
 *
 * @return list<class-string>
 */
function plugin_moresecurity_get_installable_classes(): array
{
    return [
        AttemptLog::class,
        Config::class,
        DashboardGrid::class,
        Geoip::class,
        Login::class,
        Loginip::class,
        Lostpassword::class,
        Profile::class,
        Retention::class,
        Whitelist::class,
    ];
}

/**
 * Hasta la 2.x las clases se llamaban PluginMoresecurity<Nombre> y ese nombre
 * quedó guardado en tablas del núcleo (acciones automáticas, preferencias de
 * visualización, búsquedas guardadas, historial...). Se pasa todo al nombre con
 * namespace antes de registrar nada, o las acciones automáticas se duplicarían.
 */
function plugin_moresecurity_migrate_legacy_itemtypes(Migration $migration): void
{
    /** @var \DBmysql $DB */
    global $DB;

    $classes = array_merge(plugin_moresecurity_get_installable_classes(), [DashboardCards::class, Limiter::class]);
    foreach ($classes as $fqcn) {
        $legacy = 'PluginMoresecurity' . substr(strrchr($fqcn, '\\'), 1);

        // El índice único (itemtype, name) de las acciones automáticas aborta el
        // cambio si ya existe la fila nueva: se descarta la antigua.
        $existing = array_column(iterator_to_array($DB->request([
            'SELECT' => ['name'],
            'FROM'   => 'glpi_crontasks',
            'WHERE'  => ['itemtype' => $fqcn],
        ])), 'name');
        if ($existing !== []) {
            $DB->delete('glpi_crontasks', ['itemtype' => $legacy, 'name' => $existing]);
        }

        $migration->renameItemtype($legacy, $fqcn, false);
    }
}

function plugin_moresecurity_install()
{
    $migration = new Migration(PLUGIN_MORESECURITY_VERSION);

    plugin_moresecurity_migrate_legacy_itemtypes($migration);

    foreach (plugin_moresecurity_get_installable_classes() as $classname) {
        $classname::install($migration);
    }
    $migration->executeMigration();

    return true;
}

function plugin_moresecurity_uninstall()
{
    $migration = new Migration(PLUGIN_MORESECURITY_VERSION);

    foreach (plugin_moresecurity_get_installable_classes() as $classname) {
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
    $ip = Limiter::getClientIp();
    $whitelisted = $ip && Whitelist::isWhitelisted($ip);

    if (!$whitelisted && $ip !== '') {
        // Una IP ya bloqueada se rechaza antes de evaluar el geobloqueo y sin
        // escribir nada: no hay trabajo ni filas por petición (SEV-02).
        if (Loginip::isIpBlockActive($ip)) {
            plugin_moresecurity_deny(
                401,
                [__('Too many failed login attempts from your IP. Please try again later.', 'moresecurity')],
                $suffix,
            );
        }

        // El geobloqueo es una política distinta del bloqueo por IP, pero la
        // whitelist también le vale de válvula de seguridad. Las denegaciones
        // se cuentan contra el presupuesto de la IP para que un origen
        // insistente acabe bloqueado en lugar de escribir sin límite.
        if (!Geoip::isAllowed($ip, $login)) {
            Loginip::countGeoDenial($ip);
            plugin_moresecurity_deny(
                403,
                [__('Login from your location is not permitted.', 'moresecurity')],
                $suffix,
            );
        }
    }

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
        // alimenta ningún contador (UC-08), pero el fallo sí queda en el
        // registro de seguridad.
        AttemptLog::recordFailedLogin($login, $ip);
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

    $ip = Limiter::getClientIp();
    if (!($ip && Whitelist::isWhitelisted($ip))) {
        if (Lostpassword::reserve($email, $ip) !== null) {
            plugin_moresecurity_deny(401, [__('Too many password change attempts. Please try again later.', 'moresecurity')]);
        }
    }

    AttemptLog::recordResetRequest($email, $ip);

    return $email;
}

/**
 * Presupuesto de intentos común a los canales que verifican contraseñas sin
 * pasar por el formulario web (CalDAV, REST, HL API): rechaza si la IP está
 * bloqueada o no permitida por país, reserva el intento de la cuenta antes de
 * que el núcleo verifique la contraseña y lo libera al terminar si la
 * respuesta indica que no fue un fallo.
 *
 * El bloqueo de IP y el geobloqueo se evalúan SIEMPRE, también cuando el
 * identificador no se puede analizar ($login null): un origen bloqueado no
 * debe poder seguir llegando al núcleo con un identificador mal formado.
 *
 * @param callable(int): never $refuse    responde y termina con el estado dado
 * @param callable(int): bool  $succeeded dice si el estado HTTP final libera el contador
 */
function plugin_moresecurity_enforce_login_budget(?string $login, callable $refuse, callable $succeeded): void
{
    $ip = Limiter::getClientIp();
    if ($ip !== '' && Whitelist::isWhitelisted($ip)) {
        return;
    }

    if ($ip !== '') {
        if (Loginip::isIpBlockActive($ip)) {
            $refuse(429);
        }
        if (!Geoip::isAllowed($ip, $login ?? '')) {
            Loginip::countGeoDenial($ip);
            $refuse(403);
        }
    }

    if ($login === null) {
        return;
    }

    if (Login::reserve($login, $ip) !== null) {
        $refuse(429);
    }

    register_shutdown_function(static function () use ($login, $succeeded): void {
        if ($succeeded(http_response_code() ?: 200)) {
            Login::clearLoginTry($login);
        }
    });
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

    plugin_moresecurity_enforce_login_budget(
        Limiter::cleanIdentity($user),
        static function (int $status): never {
            http_response_code($status);
            exit;
        },
        static fn(int $status): bool => $status !== 401,
    );
}

/**
 * Cuerpo de una petición de API como array (JSON u formulario), o [] si no
 * hay o no se puede analizar. Se lee con tope: solo interesan credenciales.
 *
 * @return array<string, mixed>
 */
function plugin_moresecurity_read_api_body(): array
{
    $type = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));

    try {
        $raw = file_get_contents('php://input', false, null, 0, 65536);
    } catch (SafeExceptionInterface $e) {
        return [];
    }
    if ($raw === '') {
        return [];
    }

    if (str_contains($type, 'application/json')) {
        try {
            $decoded = json_decode($raw, true);
        } catch (SafeExceptionInterface $e) {
            return [];
        }

        return is_array($decoded) ? $decoded : [];
    }

    if (str_contains($type, 'application/x-www-form-urlencoded')) {
        parse_str($raw, $parsed);

        return $parsed;
    }

    return [];
}

/**
 * Qué identidad intenta autenticarse por las APIs, con las mismas fuentes y
 * precedencia que el núcleo (APIRest::parseIncomingParams: URL < cuerpo <
 * HTTP Basic). No se mira el nombre del recurso sino la presencia de
 * credenciales, para no dejar variantes de ruta sin cubrir.
 *
 *  - REST (/apirest.php): `login`+`password` (initSession) y `email` en
 *    lostPassword. Solo si el núcleo llega a verificar la contraseña, es decir,
 *    con la API y el login por credenciales activados.
 *  - HL API (/api.php): concesión OAuth *password* (`grant_type=password`,
 *    `username`, `password`). Solo con la API activada.
 *
 * @return array{kind: 'login'|'recovery', identity: ?string}|null
 */
function plugin_moresecurity_read_api_request(string $path): ?array
{
    /** @var array $CFG_GLPI */
    global $CFG_GLPI;

    if (empty($CFG_GLPI['enable_api'])) {
        return null;
    }

    $body = plugin_moresecurity_read_api_body();
    $pick = static fn(string $key): mixed => $body[$key] ?? $_GET[$key] ?? null;

    if (preg_match('#/apirest\.php#i', $path)) {
        if (stripos($path, 'lostpassword') !== false) {
            $email = $pick('email');
            if ($email === null || $email === '') {
                return null;
            }

            return ['kind' => 'recovery', 'identity' => is_string($email) ? Limiter::cleanEmail($email) : null];
        }

        if (empty($CFG_GLPI['enable_api_login_credentials'])) {
            return null;
        }
        $login    = $pick('login');
        $password = $pick('password');
        if (isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
            $login    = $_SERVER['PHP_AUTH_USER'];
            $password = $_SERVER['PHP_AUTH_PW'];
        }
        if ($login === null || $login === '' || $password === null || $password === '') {
            return null;
        }

        return ['kind' => 'login', 'identity' => is_string($login) ? Limiter::cleanIdentity($login) : null];
    }

    if (($pick('grant_type') ?? null) !== 'password') {
        return null;
    }
    $username = $pick('username');
    if ($username === null || $username === '') {
        return null;
    }

    return ['kind' => 'login', 'identity' => is_string($username) ? Limiter::cleanIdentity($username) : null];
}

/**
 * REST (`initSession`, `lostPassword`) y HL API (`/api.php/token`, concesión
 * password): mismas reglas que el login web y la recuperación. A diferencia de
 * CalDAV, estos canales devuelven 400 (invalid_grant) y no 401 ante una
 * contraseña errónea, así que el contador solo se libera con un 200.
 */
function plugin_moresecurity_enforce_api_gate(string $path): void
{
    $request = plugin_moresecurity_read_api_request($path);
    if ($request === null) {
        return;
    }

    $is_rest = (bool) preg_match('#/apirest\.php#i', $path);
    $refuse  = static function (int $status) use ($is_rest): never {
        $message = __('Too many failed login attempts. Please try again later.', 'moresecurity');
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($is_rest ? ['ERROR_TOO_MANY_ATTEMPTS', $message] : ['error' => 'too_many_attempts', 'error_description' => $message]);
        exit;
    };

    if ($request['kind'] === 'login') {
        plugin_moresecurity_enforce_login_budget($request['identity'], $refuse, static fn(int $status): bool => $status === 200);

        return;
    }

    // lostPassword: solo el presupuesto por email y por IP.
    $ip = Limiter::getClientIp();
    if ($request['identity'] === null || ($ip !== '' && Whitelist::isWhitelisted($ip))) {
        return;
    }
    if (Lostpassword::reserve($request['identity'], $ip) !== null) {
        $refuse(429);
    }
    AttemptLog::recordResetRequest($request['identity'], $ip);
}

/**
 * Regla anti-CSRF de GLPI 12 (CheckCsrfListener) replicada para los hooks.
 *
 * Session::validateCSRF() devuelve siempre true en GLPI 12 y los hooks
 * post_init se ejecutan antes del listener de CSRF del núcleo, así que el
 * gate no puede delegar en él: sin esta comprobación un POST cross-site
 * contaría intentos y autenticaría. Una petición sin cabeceras de navegador
 * (curl, servidor a servidor) no está sujeta a CSRF, igual que en el núcleo.
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
        try {
            $origin_host = parse_url($origin, PHP_URL_HOST);
        } catch (SafeExceptionInterface $e) {
            return false;
        }
        if (!is_string($origin_host) || $origin_host === '') {
            return false;
        }
        try {
            $origin_port = parse_url($origin, PHP_URL_PORT);
        } catch (SafeExceptionInterface $e) {
            return false;
        }

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
 * - Antes de autenticar o escribir contadores exige una petición same-origin
 *   (MS-07, regla de cabeceras de GLPI 12). Si no lo es no se hace nada y el
 *   control CSRF nativo rechaza la petición después.
 */
function plugin_moresecurity_enforce_login_gate(): void
{
    /** @var array $CFG_GLPI */
    global $CFG_GLPI;

    try {
        $path = rawurldecode((string) parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH));
        $path = preg_replace('#/+#', '/', $path);
    } catch (SafeExceptionInterface $e) {
        // URI imposible de analizar: mismo resultado que antes (ruta vacía).
        $path = '';
    }

    // CalDAV verifica contraseñas con HTTP Basic en cualquier método.
    // Mismo criterio que el core (SessionManager: str_starts_with '/caldav.php'): la
    // ruta del controlador es `/caldav.php{.*}`, así que `/caldav.phpX` también
    // llega al servidor CalDAV y valida la contraseña Basic.
    if (preg_match('#/caldav\.php#', $path)) {
        plugin_moresecurity_enforce_caldav_gate();
    }

    // REST y HL API verifican contraseñas con cualquier verbo (initSession por
    // GET, lostPassword por PUT) y con nombres de campo distintos del formulario.
    if (preg_match('#/api(rest)?\.php#i', $path)) {
        plugin_moresecurity_enforce_api_gate($path);
    }

    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        return;
    }

    if (isset($_POST['login_name']) || isset($_POST['login_password'])) {
        // Ningún otro script del núcleo procesa credenciales: se atiende
        // cualquier ruta, no solo las conocidas, para no dejar atajos.
        // Una petición cross-site no se procesa aquí: el listener CSRF del
        // núcleo corre después de este hook, así que se corta antes de tocar
        // contadores o autenticar (Session::validateCSRF() ya no valida).
        if (!plugin_moresecurity_is_csrf_safe()) {
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

    // initpassword.php envía el evento `passwordinit`; el resto, `passwordforget`:
    // el gate se activa con la misma notificación que exige el núcleo para la ruta.
    $recovery_event = preg_match('#/front/initpassword\.php(/|$)#', $path) === 1 ? 'passwordinit' : 'passwordforget';
    if (
        isset($_POST['email'])
        && !isset($_REQUEST['password_forget_token'])
        && preg_match('#/(front/lostpassword\.php|front/initpassword\.php|plugins/moresecurity/front/lostpassword\.form\.php)(/|$)#', $path)
        && $CFG_GLPI['notifications_mailing']
        && countElementsInTable('glpi_notifications', ['itemtype' => 'User', 'event' => $recovery_event, 'is_active' => 1])
    ) {
        // Cross-site: no se cuenta nada y el control CSRF nativo la rechaza
        // (403) después; si se admite, continúa hacia el controlador.
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
