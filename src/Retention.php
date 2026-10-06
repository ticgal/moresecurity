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

namespace GlpiPlugin\Moresecurity;

use CommonDBTM;
use CronTask;
use DBmysql;
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

    public static function getTypeName($nb = 0): string
    {
        return 'More Security';
    }

    public static function cronInfo($name): array
    {
        return [
            'description' => __('Purge old login and password reset attempt records', 'moresecurity'),
        ];
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

        $deleted = 0;
        for ($i = 0; $i < $max_batches; $i++) {
            $DB->doQuery(
                "DELETE FROM " . DBmysql::quoteName($table) . "
                 WHERE (`blocked` IS NULL OR `blocked` <= NOW())
                   AND (`last_try` IS NULL OR `last_try` < (NOW() - INTERVAL " . max(1, $retention_days) . " DAY))
                 LIMIT " . (int) $batch,
            );
            $count = (int) $DB->getAffectedRows();
            $deleted += $count;
            if ($count < $batch) {
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
    }

    public static function uninstall(Migration $migration): void
    {
        CronTask::unregister('moresecurity');
    }
}
