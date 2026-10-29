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

use CommonDBTM;
use CronTask;
use Glpi\DBAL\QueryFunction;
use Migration;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

/**
 * Retención de datos de intentos (MS-08): acción automática diaria que borra
 * por lotes las filas inactivas y sin bloqueo vigente.
 */
class Retention extends CommonDBTM
{
    public const RETENTION_DAYS = 7;

    // Días que se conserva el registro de seguridad (parámetro de la acción
    // automática "PurgeLogs", editable desde su ficha).
    public const LOG_RETENTION_DAYS = 30;

    public static function getTypeName($nb = 0): string
    {
        return 'More Security';
    }

    public static function cronInfo($name): array
    {
        if ($name === 'PurgeLogs') {
            return [
                'description' => __('Purge security logs based on retention policy', 'moresecurity'),
                'parameter'   => __('Retention period (days)', 'moresecurity'),
            ];
        }

        return [
            'description' => __('Purge old login and password reset attempt records', 'moresecurity'),
        ];
    }

    /**
     * @param CronTask $task
     */
    public static function cronPurgeLogs($task): int
    {
        $days  = max(1, (int) ($task->fields['param'] ?? self::LOG_RETENTION_DAYS));
        $total = AttemptLog::purge($days);

        $task->addVolume($total);

        return $total > 0 ? 1 : 0;
    }

    /**
     * @param CronTask $task
     */
    public static function cronPurge($task): int
    {
        $total  = Login::purge(self::RETENTION_DAYS);
        $total += Loginip::purge(self::RETENTION_DAYS);
        $total += Lostpassword::purge(self::RETENTION_DAYS);

        $task->addVolume($total);

        return $total > 0 ? 1 : 0;
    }

    /**
     * Borra filas sin actividad en $retention_days días y sin bloqueo vigente,
     * y las que quedaron a cero tras un login correcto. LIMIT por lote para no
     * mantener bloqueos largos sobre la tabla.
     */
    public static function purgeTable(string $table, int $retention_days, int $batch = 1000, int $max_batches = 50): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $now   = QueryFunction::now();
        $where = [
            ['OR' => [['blocked' => null], ['blocked' => ['<=', $now]]]],
            ['OR' => [['last_try' => null], ['last_try' => ['<', QueryFunction::dateSub($now, max(1, $retention_days), 'DAY')]]]],
        ];

        $deleted = 0;
        for ($i = 0; $i < $max_batches; $i++) {
            // DBmysql::delete() no admite LIMIT: ids del lote y borrado por clave.
            $ids = array_column(iterator_to_array($DB->request([
                'SELECT' => 'id',
                'FROM'   => $table,
                'WHERE'  => $where,
                'LIMIT'  => $batch,
            ]), false), 'id');
            if ($ids === []) {
                break;
            }
            $DB->delete($table, ['id' => $ids]);
            $deleted += count($ids);
            if (count($ids) < $batch) {
                break;
            }
        }

        return $deleted;
    }

    public static function install(Migration $migration): void
    {
        CronTask::register(
            self::class,
            'Purge',
            DAY_TIMESTAMP,
            [
                'comment' => __('Purge old login and password reset attempt records', 'moresecurity'),
                'mode'    => CronTask::MODE_INTERNAL,
            ],
        );

        CronTask::register(
            self::class,
            'PurgeLogs',
            DAY_TIMESTAMP,
            [
                'comment' => __('Purge security logs based on retention policy', 'moresecurity'),
                'mode'    => CronTask::MODE_INTERNAL,
                'param'   => self::LOG_RETENTION_DAYS,
            ],
        );
    }

    public static function uninstall(Migration $migration): void
    {
        CronTask::unregister('moresecurity');
    }
}
