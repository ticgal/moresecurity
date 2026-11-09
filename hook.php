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
use GlpiPlugin\Moresecurity\VerifiedLogin;
use GlpiPlugin\Moresecurity\Whitelist;
use Safe\Exceptions\SafeExceptionInterface;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

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
 * Ruta tal como la enruta el núcleo: el path info de Symfony (sin el
 * subdirectorio de instalación ni un `/index.php` delante), decodificado como
 * hace el UrlMatcher. Los controladores de CalDAV, REST y HL API se declaran
 * como `/caldav.php{.*}`, `/apirest.php{.*}` y `/api.php{.*}`, así que una
 * ruta solo llega a ellos si EMPIEZA por esos prefijos.
 */
function plugin_moresecurity_get_route_path(): string
{
    try {
        $path_info = (new SymfonyRequest(server: $_SERVER))->getPathInfo();
    } catch (Throwable $e) {
        return '';
    }

    return rawurldecode($path_info);
}

/**
 * Forma en texto que tendrá un identificador recibido por la API cuando el
 * núcleo lo use (coerción escalar de PHP: 123 → "123", true → "1"), o null si
 * no es escalar: el núcleo no llega a verificar un array u objeto.
 */
function plugin_moresecurity_scalar_string(mixed $value): ?string
{
    return is_scalar($value) ? (string) $value : null;
}

/**
 * Presupuesto de intentos común a los canales que verifican contraseñas sin
 * pasar por el formulario web (CalDAV, REST, HL API): rechaza si la IP está
 * bloqueada o no permitida por país y reserva el intento de la cuenta antes de
 * que el núcleo verifique la contraseña.
 *
 * Al terminar, el intento solo se libera si el núcleo autenticó de verdad esa
 * cuenta en esta petición (VerifiedLogin). Nunca por el código HTTP: una ruta
 * que responde sin verificar contraseñas no puede borrar los contadores.
 *
 * $login null significa que la petición no trae credenciales que el núcleo
 * vaya a verificar. El bloqueo de IP y el geobloqueo se evalúan igualmente:
 * un origen bloqueado no debe seguir llegando al núcleo.
 *
 * @param callable(int): never $refuse responde y termina con el estado dado
 */
function plugin_moresecurity_enforce_login_budget(?string $login, callable $refuse): void
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

    register_shutdown_function(static function () use ($login): void {
        if (VerifiedLogin::isVerified($login)) {
            Login::clearLoginTry($login);
        }
    });
}

/**
 * Usuario de HTTP Basic tal como lo verá el servidor CalDAV (sabre/http): la
 * cabecera Authorization se reconstruye desde $_SERVER igual que en
 * Sapi::createFromServerArray() (gana la última fuente) y se decodifica igual
 * que en Auth\Basic::getCredentials() (base64 no estricto). Null si no hay
 * credenciales Basic.
 */
function plugin_moresecurity_read_caldav_user(): ?string
{
    $header = null;
    foreach ($_SERVER as $key => $value) {
        $key = (string) $key;
        if ($key === 'PHP_AUTH_USER') {
            if (isset($_SERVER['PHP_AUTH_PW'])) {
                $header = 'Basic ' . base64_encode((string) $value . ':' . (string) $_SERVER['PHP_AUTH_PW']);
            }
        } elseif ($key === 'PHP_AUTH_DIGEST') {
            $header = 'Digest ' . (string) $value;
        } elseif ($key === 'REDIRECT_HTTP_AUTHORIZATION' || $key === 'HTTP_AUTHORIZATION') {
            $header = (string) $value;
        }
    }

    if ($header === null || strtolower(substr($header, 0, 6)) !== 'basic ') {
        return null;
    }

    $decoded = base64_decode(substr($header, 6));
    if (!is_string($decoded)) {
        return null;
    }
    $credentials = explode(':', $decoded, 2);

    return count($credentials) === 2 ? $credentials[0] : null;
}

/**
 * CalDAV (/caldav.php, HTTP Basic): mismas reglas que el login web. Se
 * rechaza si la IP o la cuenta están bloqueadas o la IP no está permitida; el
 * intento se reserva antes y solo se libera si el núcleo autenticó la cuenta.
 */
function plugin_moresecurity_enforce_caldav_gate(): void
{
    $refuse = static function (int $status): never {
        http_response_code($status);
        exit;
    };

    $user  = plugin_moresecurity_read_caldav_user();
    $login = null;
    if ($user !== null && trim($user) !== '') {
        // El núcleo verificaría la contraseña de esta identidad: si no se
        // puede contar (caracteres de control, longitud) se rechaza, igual
        // que en el login web, en vez de dejarla pasar sin presupuesto.
        $login = Limiter::cleanIdentity($user);
        if ($login === null) {
            $refuse(400);
        }
    }

    plugin_moresecurity_enforce_login_budget($login, $refuse);
}

/**
 * Cuerpo completo de la petición, como lo lee el núcleo (API::getHttpBody(),
 * HL ApiController).
 */
function plugin_moresecurity_read_input(): string
{
    try {
        return file_get_contents('php://input');
    } catch (SafeExceptionInterface $e) {
        return '';
    }
}

/**
 * Decodifica JSON a array; null si no es JSON válido o no es un array/objeto.
 *
 * @return array<array-key, mixed>|null
 */
function plugin_moresecurity_decode_json_array(string $json): ?array
{
    try {
        $decoded = json_decode($json, true);
    } catch (SafeExceptionInterface $e) {
        return null;
    }

    return is_array($decoded) ? $decoded : null;
}

/**
 * Parámetros de una petición REST (`/apirest.php`, `/api.php/v1`) con las
 * mismas fuentes, precedencia y conversiones que APIRest::parseIncomingParams():
 * URL < cuerpo (JSON si no hay Content-Type, `uploadManifest` en multipart,
 * formulario) < HTTP Basic, y los valores "true"/"false" pasan a booleanos.
 *
 * @return array<array-key, mixed>
 */
function plugin_moresecurity_read_rest_params(): array
{
    $params = [];
    parse_str((string) ($_SERVER['QUERY_STRING'] ?? ''), $params);

    $content_type = (string) ($_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? 'application/json');

    $body_params = [];
    if (str_contains($content_type, 'application/json')) {
        $body = trim(plugin_moresecurity_read_input());
        if ($body !== '') {
            // JSON inválido: el núcleo responde 400 sin verificar nada.
            $body_params = plugin_moresecurity_decode_json_array($body) ?? [];
        }
    } elseif (str_contains($content_type, 'multipart/form-data')) {
        // Con multipart php://input llega vacío: el núcleo lee el manifiesto
        // (y exige al menos un fichero adjunto).
        $manifest = $_REQUEST['uploadManifest'] ?? null;
        if (count($_FILES) > 0 && is_string($manifest)) {
            $body_params = plugin_moresecurity_decode_json_array($manifest) ?? [];
        }
    } elseif (str_contains($content_type, 'application/x-www-form-urlencoded')) {
        parse_str(trim(plugin_moresecurity_read_input()), $body_params);
    }
    foreach ($body_params as $key => $value) {
        $params[$key] = $value;
    }

    if (isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
        $params['login']    = $_SERVER['PHP_AUTH_USER'];
        $params['password'] = $_SERVER['PHP_AUTH_PW'];
    }

    foreach ($params as $key => $value) {
        if ($value === 'true') {
            $params[$key] = true;
        } elseif ($value === 'false') {
            $params[$key] = false;
        }
    }

    return $params;
}

/**
 * Parámetros de una petición a la HL API con las mismas fuentes y precedencia
 * que Router::handleRequest(): $_REQUEST (consulta, formulario y multipart) y,
 * si el Content-Type es exactamente application/json, el cuerpo JSON encima.
 *
 * @return array<array-key, mixed>
 */
function plugin_moresecurity_read_hl_params(): array
{
    $params = $_REQUEST;

    $content_type = explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? ''))[0];
    if ($content_type === 'application/json') {
        $body = plugin_moresecurity_decode_json_array(plugin_moresecurity_read_input());
        if ($body === null) {
            return []; // el núcleo responde 400 sin invocar la ruta
        }
        foreach ($body as $key => $value) {
            $params[(string) $key] = $value;
        }
    }

    return $params;
}

/**
 * HL API: concesión OAuth *password* en `POST /api.php[/vX.Y]/token`
 * (`grant_type=password`, `username`, `password`), con el mismo criterio que
 * ApiController (prefijo de versión), Router::matchAll() (ruta sin distinguir
 * mayúsculas) y League (AbstractGrant::parseParam(): cualquier escalar, como
 * texto recortado).
 *
 * @return array{kind: 'login', channel: 'hl', identity: ?string}|null
 */
function plugin_moresecurity_read_hl_token_request(string $relative): ?array
{
    if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? '')) !== 'POST') {
        return null;
    }
    $relative = preg_replace('#^/v\d+(?:\.\d+)*/#', '/', $relative);
    if (!is_string($relative) || strtolower($relative) !== '/token') {
        return null;
    }

    $params = plugin_moresecurity_read_hl_params();
    if (($params['grant_type'] ?? null) !== 'password') {
        return null;
    }

    $username = plugin_moresecurity_scalar_string($params['username'] ?? null);
    $password = plugin_moresecurity_scalar_string($params['password'] ?? null);
    if ($username === null || trim($username) === '' || $password === null || trim($password) === '') {
        return null;
    }

    return ['kind' => 'login', 'channel' => 'hl', 'identity' => Limiter::cleanIdentity($username)];
}

/**
 * Qué intento de autenticación lleva una petición a las APIs, decidido con la
 * misma ruta y los mismos parámetros que usará el núcleo:
 *
 *  - REST (`/apirest.php…` y `/api.php/v1…`, ApiController los envía al mismo
 *    APIRest): recurso `initSession` con `login`+`password` (si el login por
 *    credenciales está activado) y `lostPassword` con `email`. Solo con la API
 *    REST activada.
 *  - HL API (`POST /api.php[/vX]/token`, concesión *password*): el núcleo la
 *    atiende aunque la API REST esté desactivada (e incluso con la HL API
 *    desactivada), así que no depende de ninguna de las dos opciones.
 *
 * `identity` null en un login significa que el núcleo verificaría una
 * identidad que el plugin no puede contar: la petición se rechaza.
 *
 * @return array{kind: 'login'|'recovery', channel: 'rest'|'hl', identity: ?string}|null
 */
function plugin_moresecurity_read_api_request(string $route): ?array
{
    /** @var array $CFG_GLPI */
    global $CFG_GLPI;

    if (str_starts_with($route, '/apirest.php')) {
        $rest_info = substr($route, strlen('/apirest.php'));
    } elseif (str_starts_with($route, '/api.php')) {
        $info     = substr($route, strlen('/api.php'));
        $relative = '/' . trim($info, '/');
        if (preg_match('#^/v1(/|$)#', $relative) !== 1) {
            return plugin_moresecurity_read_hl_token_request($relative);
        }
        $rest_info = $info;
    } else {
        return null;
    }

    if (empty($CFG_GLPI['enable_api'])) {
        return null;
    }

    // Recurso solicitado, calculado igual que APIRest::call().
    $rest_info = str_replace('api/', '', $rest_info);
    $rest_info = str_replace('v1/', '', $rest_info);
    $resource  = trim(explode('/', trim($rest_info, '/'))[0]);

    if ($resource === 'lostPassword') {
        $params = plugin_moresecurity_read_rest_params();
        // Con password_forget_token el núcleo completa un cambio de
        // contraseña y no envía ningún correo.
        if (!isset($params['email']) || isset($params['password_forget_token'])) {
            return null;
        }
        $email = $params['email'];

        return ['kind' => 'recovery', 'channel' => 'rest', 'identity' => is_string($email) ? Limiter::cleanEmail($email) : null];
    }

    if ($resource !== 'initSession' || empty($CFG_GLPI['enable_api_login_credentials'])) {
        return null;
    }

    // Mismo criterio que API::initSession() para usar login y contraseña.
    $params   = plugin_moresecurity_read_rest_params();
    $login    = $params['login'] ?? '';
    $password = $params['password'] ?? '';
    if ($login === '' || $password === '') {
        return null;
    }
    $login = plugin_moresecurity_scalar_string($login);
    if ($login === null || trim($login) === '') {
        return null; // array, objeto o false: el núcleo no llega a verificarlo
    }

    return ['kind' => 'login', 'channel' => 'rest', 'identity' => Limiter::cleanIdentity($login)];
}

/**
 * REST (`initSession`, `lostPassword`) y HL API (`/api.php/token`, concesión
 * password): mismas reglas que el login web y la recuperación.
 */
function plugin_moresecurity_enforce_api_gate(string $route): void
{
    $request = plugin_moresecurity_read_api_request($route);
    if ($request === null) {
        return;
    }

    $is_rest = $request['channel'] === 'rest';
    $respond = static function (int $status, string $code, string $message) use ($is_rest): never {
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($is_rest ? [$code, $message] : ['error' => strtolower(substr($code, 6)), 'error_description' => $message]);
        exit;
    };
    $refuse = static function (int $status) use ($respond): never {
        $respond($status, 'ERROR_TOO_MANY_ATTEMPTS', __('Too many failed login attempts. Please try again later.', 'moresecurity'));
    };

    if ($request['kind'] === 'login') {
        if ($request['identity'] === null) {
            $respond(400, 'ERROR_INVALID_LOGIN', __('Incorrect username or password'));
        }
        if ($request['channel'] === 'hl') {
            VerifiedLogin::listenOAuth();
        }
        plugin_moresecurity_enforce_login_budget($request['identity'], $refuse);

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

    // Los canales que verifican contraseñas fuera del formulario se reconocen
    // por la ruta que enruta el núcleo (path info de Symfony), anclada al
    // comienzo como en sus controladores: `/caldav.php{.*}` (así que
    // `/caldav.phpX` también llega al servidor CalDAV), `/apirest.php{.*}` y
    // `/api.php{.*}`. Así cubre instalaciones en subdirectorio y rutas con
    // `/index.php` delante, y no se dispara en rutas que solo contienen el
    // nombre (`/noexiste/caldav.php`).
    $route = plugin_moresecurity_get_route_path();

    // CalDAV verifica contraseñas con HTTP Basic en cualquier método.
    if (str_starts_with($route, '/caldav.php')) {
        plugin_moresecurity_enforce_caldav_gate();
    }

    // REST y HL API verifican contraseñas con cualquier verbo (initSession por
    // GET, lostPassword por PUT) y con nombres de campo distintos del formulario.
    if (str_starts_with($route, '/apirest.php') || str_starts_with($route, '/api.php')) {
        plugin_moresecurity_enforce_api_gate($route);
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
