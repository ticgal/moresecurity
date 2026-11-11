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

use Glpi\OAuth\Server;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use Session;
use Throwable;
use User;

if (!defined('GLPI_ROOT')) {
    echo "Sorry. You can't access directly to this file";
    return;
}

/**
 * Señal positiva de que el núcleo ha verificado la contraseña de una cuenta
 * en la petición en curso (canales CalDAV, REST y HL API).
 *
 * El intento reservado antes de que el núcleo actúe solo se libera con esta
 * señal, nunca por el código HTTP de la respuesta: una respuesta 200/404 de
 * una ruta que no verifica contraseñas no puede borrar los contadores.
 *
 * - CalDAV y REST (`initSession`): tras validar la contraseña el núcleo llama
 *   a Session::init(), que deja en la sesión el usuario autenticado.
 * - HL API (concesión OAuth *password*): no abre sesión; el servidor OAuth del
 *   núcleo emite `access_token.issued` con el usuario al que entrega el token.
 */
final class VerifiedLogin
{
    /** @var array<int, true> usuarios que han recibido un token OAuth en esta petición */
    private static array $oauth_users = [];

    private static bool $oauth_listening = false;

    /**
     * Empieza a escuchar los tokens que emita el servidor OAuth del núcleo en
     * esta petición. Es el mismo singleton que atiende `/api.php/token`.
     */
    public static function listenOAuth(): void
    {
        if (self::$oauth_listening) {
            return;
        }

        try {
            Server::getAuthorizationServer()->getEmitter()->subscribeTo(
                RequestEvent::ACCESS_TOKEN_ISSUED,
                static function (object $event): void {
                    if (!$event instanceof RequestAccessTokenEvent) {
                        return;
                    }
                    $users_id = $event->getAccessToken()->getUserIdentifier();
                    if (is_string($users_id) && ctype_digit($users_id)) {
                        self::$oauth_users[(int) $users_id] = true;
                    }
                },
            );
            self::$oauth_listening = true;
        } catch (Throwable $e) {
            // Sin claves OAuth el núcleo tampoco puede emitir tokens: no habrá
            // señal y el intento reservado no se libera (falla cerrado).
        }
    }

    /**
     * ¿Ha autenticado el núcleo, en esta petición, a la cuenta `$login`?
     *
     * La comparación del nombre la hace la base de datos con la misma
     * colación con la que el núcleo buscó al usuario a partir de lo tecleado.
     */
    public static function isVerified(string $login): bool
    {
        $users_ids = array_keys(self::$oauth_users);

        $session_user = Session::getLoginUserID();
        if (is_int($session_user) || (is_string($session_user) && ctype_digit($session_user))) {
            $users_ids[] = (int) $session_user;
        }

        $login = trim($login);
        if ($users_ids === [] || $login === '') {
            return false;
        }

        return countElementsInTable(User::getTable(), ['id' => $users_ids, 'name' => $login]) > 0;
    }
}
