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

use CronTask;
use GeoIp2\Database\Reader;
use Glpi\Event;
use Glpi\Toolbox\HttpClient;
use Migration;
use Safe\Exceptions\SafeExceptionInterface;

use function Safe\chmod;
use function Safe\fclose;
use function Safe\file_put_contents;
use function Safe\fopen;
use function Safe\fwrite;
use function Safe\gzclose;
use function Safe\gzopen;
use function Safe\gzread;
use function Safe\mkdir;
use function Safe\rename;
use function Safe\tempnam;
use function Safe\unlink;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

/**
 * Resolves client IPs to ISO-3166-1 alpha-2 country codes using a DB-IP Lite
 * `.mmdb` database, and enforces the configured allow/deny country policy on
 * logins. Every failure mode (missing/corrupt database, unresolvable IP)
 * fails open — this plugin never locks everyone out on a data problem.
 */
class Geoip
{
    /**
     * In-request cache so a single request never opens the mmdb reader twice.
     */
    private static ?Reader $reader = null;
    private static bool $reader_load_attempted = false;

    public const MODE_DISABLED = 'disabled';
    public const MODE_ALLOW = 'allow';
    public const MODE_DENY = 'deny';
    public const MODES = [self::MODE_DISABLED, self::MODE_ALLOW, self::MODE_DENY];

    /**
     * Absolute path to the stored DB-IP Lite `.mmdb` file, outside the webroot.
     */
    public static function getDatabasePath(): string
    {
        return GLPI_PLUGIN_DOC_DIR . '/moresecurity/_geoip/dbip-country-lite.mmdb';
    }

    /**
     * DB-IP Lite Country's free, no-account monthly download URL. The file
     * name embeds the current year-month; DB-IP keeps every past month's
     * release available at the same pattern.
     */
    public static function getDownloadUrl(): string
    {
        return 'https://download.db-ip.com/free/dbip-country-lite-' . date('Y-m') . '.mmdb.gz';
    }

    /**
     * Download the current month's DB-IP Lite Country database and install
     * it atomically (temp file + rename) so a concurrent lookup never reads
     * a half-written file.
     *
     * @return bool true on success
     */
    public static function downloadDatabase(): bool
    {
        $target = self::getDatabasePath();
        $dir = dirname($target);
        $gz_tmp = null;
        $tmp = null;
        $ok = false;

        try {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }

            // Unique temp names: two concurrent runs must not overwrite each other.
            $gz_tmp = tempnam($dir, 'dbip-gz-');
            $tmp = tempnam($dir, 'dbip-mmdb-');

            if (self::fetchAndInflate($gz_tmp, $tmp) && self::isValidDatabase($tmp)) {
                chmod($tmp, 0644);
                // Atomic replace: a concurrent lookup never reads a half-written
                // file, and a failed update keeps the previous database.
                rename($tmp, $target);
                $ok = true;
            }
        } catch (\Throwable $e) {
            $ok = false;
        } finally {
            self::removeFile($gz_tmp);
            self::removeFile($tmp); // no-op after a successful rename
        }

        if ($ok) {
            // Force the in-request cache to reopen against the freshly written file.
            self::$reader = null;
            self::$reader_load_attempted = false;
        }

        return $ok;
    }

    /**
     * Delete a file if it exists; never throws (cleanup must not mask the
     * real outcome of the download).
     */
    private static function removeFile(?string $path): void
    {
        if ($path === null || !is_file($path)) {
            return;
        }

        try {
            unlink($path);
        } catch (SafeExceptionInterface $e) {
            // Nothing else to do: a stale temp file is harmless and is not reused.
        }
    }

    /**
     * Download the gzip into $gz_tmp (capped while receiving, not after) and
     * inflate it into $tmp (capped against decompression bombs).
     *
     * @throws SafeExceptionInterface on any filesystem or gzip failure
     */
    private static function fetchAndInflate(string $gz_tmp, string $tmp): bool
    {
        // The real DB-IP Lite Country file is a few MB compressed / ~8 MB
        // inflated; these caps only bound the damage from a bad response.
        $max_download = 40 * 1024 * 1024;
        $max_inflated = 50 * 1024 * 1024;

        try {
            $response = (new HttpClient())->request(
                'GET',
                self::getDownloadUrl(),
                [
                    'timeout'     => 60,
                    'max_duration' => 300,
                    // Throwing from here aborts the transfer (covers chunked
                    // responses that announce no Content-Length).
                    'on_progress' => static function (int $dl_now, int $dl_size) use ($max_download): void {
                        if ($dl_now > $max_download || $dl_size > $max_download) {
                            throw new \RuntimeException('DB-IP download exceeds the size cap');
                        }
                    },
                ],
            );
            $content = $response->getContent();
        } catch (\Throwable $e) {
            return false;
        }
        if ($content === '' || strlen($content) > $max_download) {
            return false;
        }
        file_put_contents($gz_tmp, $content);
        unset($content);

        $gz = gzopen($gz_tmp, 'rb');
        $out = fopen($tmp, 'wb');

        $written = 0;
        $too_large = false;
        try {
            while (!gzeof($gz)) {
                $chunk = gzread($gz, 1024 * 1024);
                $written += strlen($chunk);
                if ($written > $max_inflated) {
                    $too_large = true;
                    break;
                }
                fwrite($out, $chunk);
            }
        } finally {
            fclose($out);
            gzclose($gz);
        }

        return !$too_large && $written > 0;
    }

    /**
     * The file must open as a MaxMind DB and be a country database before it
     * replaces the current one; anything else would leave geoblocking
     * silently failing open.
     */
    private static function isValidDatabase(string $path): bool
    {
        try {
            $reader = new Reader($path);
            $type = (string) $reader->metadata()->databaseType;
            $reader->close();

            return stripos($type, 'country') !== false;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Open (and cache for the rest of the request) the mmdb reader.
     *
     * @return Reader|null null if the database is missing/corrupt
     */
    private static function getReader(): ?Reader
    {
        if (self::$reader !== null) {
            return self::$reader;
        }
        if (self::$reader_load_attempted) {
            return null;
        }
        self::$reader_load_attempted = true;

        $path = self::getDatabasePath();
        if (!file_exists($path)) {
            return null;
        }

        try {
            self::$reader = new Reader($path);
        } catch (\Throwable $e) {
            self::$reader = null;
        }

        return self::$reader;
    }

    /**
     * Sentinel stored/matched for a private (RFC 1918/loopback/link-local) address.
     */
    public const PRIVATE_RANGE = 'PRIVATE';

    /**
     * Sentinel stored/matched for a reserved/unassigned address (e.g. RFC 5737
     * documentation ranges) — never routable, so it can never carry a real country.
     */
    public const RESERVED_RANGE = 'RESERVED';

    /**
     * Sentinel stored/matched for a routable address whose country genuinely
     * couldn't be resolved (missing/corrupt database, or no record for that IP).
     */
    public const UNKNOWN = 'UNKNOWN';

    /**
     * Classify an IP into either a real ISO-3166-1 alpha-2 country code, or one
     * of the PRIVATE_RANGE / RESERVED_RANGE / UNKNOWN sentinels above. Never
     * returns null — every IP classifies as something.
     *
     * @param  string $ip
     * @return string ISO-3166-1 alpha-2 code, or a sentinel constant
     */
    public static function classifyIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return self::UNKNOWN;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false) {
            return self::PRIVATE_RANGE;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE) === false) {
            return self::RESERVED_RANGE;
        }

        $reader = self::getReader();
        if ($reader === null) {
            return self::UNKNOWN;
        }

        try {
            $record = $reader->country($ip);
            return $record->country->isoCode ?: self::UNKNOWN;
        } catch (\Throwable $e) {
            return self::UNKNOWN;
        }
    }

    /**
     * Resolve an IP to its ISO-3166-1 alpha-2 country code, for the geoblocking
     * allow/deny decision only — a sentinel from classifyIp() is not a real
     * country, so it's normalized to null here and callers must fail open on it.
     *
     * @param  string $ip
     * @return string|null null on any non-country classification (private,
     *                      reserved, or unknown) — callers must fail open on null.
     */
    public static function getCountryCode(string $ip): ?string
    {
        $classification = self::classifyIp($ip);

        return in_array($classification, [self::PRIVATE_RANGE, self::RESERVED_RANGE, self::UNKNOWN], true)
            ? null
            : $classification;
    }

    /**
     * Human-readable name for a stored country code or sentinel, for display in
     * the Security Log and dashboard cards. `null`/empty (legacy rows written
     * before the PRIVATE/RESERVED/UNKNOWN split) falls back to the "Unknown" label.
     *
     * @param  string|null $code ISO-3166-1 alpha-2 code, a sentinel constant, or null
     * @return string
     */
    public static function getCountryDisplayName(?string $code): string
    {
        switch ($code) {
            case self::PRIVATE_RANGE:
                return __('Private', 'moresecurity');
            case self::RESERVED_RANGE:
                return __('Reserved', 'moresecurity');
            case self::UNKNOWN:
            case null:
            case '':
                return __('Unknown', 'moresecurity');
        }

        $names = self::getCountryNames();

        return $names[$code] ?? $code;
    }

    /**
     * ISO-3166-1 alpha-2 code => country name, sorted by name. Empty when the
     * league/iso3166 dependency is not installed (the plugin then degrades to
     * showing raw codes instead of failing).
     *
     * @return array<string,string>
     */
    public static function getCountryNames(): array
    {
        static $names = null;
        if ($names === null) {
            $names = [];
            if (class_exists(\League\ISO3166\ISO3166::class)) {
                foreach ((new \League\ISO3166\ISO3166())->all() as $country) {
                    $names[$country['alpha2']] = $country['name'];
                }
                asort($names);
            }
        }

        return $names;
    }

    /**
     * The three non-country sentinels, in the fixed display/sort order they
     * must always appear before real countries in filters and dashboard cards.
     *
     * @return string[]
     */
    public static function getNonCountrySentinels(): array
    {
        return [self::PRIVATE_RANGE, self::RESERVED_RANGE, self::UNKNOWN];
    }

    /**
     * Decide whether a login from the given IP is allowed under the
     * configured geoblocking mode, and record the outcome (denial → audit
     * log; lookup failure → native Events log, per README/plan).
     *
     * @param  string $ip
     * @param  string $identifier login/username being authenticated
     * @return bool true if the login may proceed
     */
    public static function isAllowed(string $ip, string $identifier): bool
    {
        $config = Config::getInstance();
        $mode = $config->fields['geoblock_mode'] ?? self::MODE_DISABLED;

        if ($mode === self::MODE_DISABLED) {
            return true;
        }

        $country = self::getCountryCode($ip);
        if ($country === null) {
            self::logLookupFailure($ip);
            return true;
        }

        $countries = array_filter(
            array_map(
                'trim',
                explode(',', (string) ($config->fields['geoblock_countries'] ?? '')),
            ),
        );

        $in_list = in_array($country, $countries, true);
        $allowed = ($mode === self::MODE_ALLOW) ? $in_list : !$in_list;

        if (!$allowed) {
            AttemptLog::logGeoBlock($ip, $identifier, $country);
        }

        return $allowed;
    }

    /**
     * Surface GeoIP *lookup failures* (not denials) in GLPI's native Events
     * log — this is an operational signal (missing/corrupt database, or a
     * private/local address usually pointing at a proxy misconfiguration),
     * not a routine denial, so it doesn't belong in the plugin's own audit
     * trail alongside EVENT_LOGIN_GEO rows.
     */
    private static function logLookupFailure(string $ip): void
    {
        // Como mucho un aviso por hora: sin esto cada login escribiría una
        // fila en `glpi_events` (SEV-02).
        /** @var \Psr\SimpleCache\CacheInterface $GLPI_CACHE */
        global $GLPI_CACHE;
        $cache_key = 'moresecurity_geoip_lookup_failed';
        if ($GLPI_CACHE->has($cache_key)) {
            return;
        }
        $GLPI_CACHE->set($cache_key, 1, HOUR_TIMESTAMP);

        $reason = file_exists(self::getDatabasePath())
        ? __('private/local address', 'moresecurity')
        : __('database unavailable', 'moresecurity');

        Event::log(
            0,
            "system",
            3,
            "login",
            sprintf(
                __('GeoIP lookup failed for IP %1$s (%2$s) — login allowed through (fail-open)', 'moresecurity'),
                $ip,
                $reason,
            ),
        );
    }

    /**
     * Cron description for 'updatedb', displayed on the CronTask configuration form.
     */
    public static function cronInfo(string $name): array
    {
        return match ($name) {
            'updatedb' => [
                'description' => __('Download the monthly DB-IP Lite country database', 'moresecurity'),
            ],
            default => [],
        };
    }

    /**
     * CronTask: refresh the DB-IP Lite database. DB-IP republishes Lite
     * monthly, so this is registered on a 30-day cadence, not daily.
     *
     * @param  CronTask $task
     * @return int 1 on success, 0 on failure (GLPI cron return code, not a CronTask::STATE_* constant)
     */
    public static function cronUpdateDb(CronTask $task): int
    {
        // Sin geobloqueo activo no se hace ninguna petición saliente, salvo
        // que aún no haya base de datos (así existe al activar el modo).
        $mode = Config::getInstance()->fields['geoblock_mode'] ?? self::MODE_DISABLED;
        if ($mode === self::MODE_DISABLED && is_file(self::getDatabasePath())) {
            return 0;
        }

        $ok = self::downloadDatabase();

        if ($ok) {
            $task->addVolume(1);
            $task->log(__('GeoIP database updated successfully.', 'moresecurity'));
            return 1;
        }

        $task->log(__('GeoIP database update failed.', 'moresecurity'));
        return 0;
    }

    public static function install(Migration $migration): void
    {
        // 30 days: DB-IP republishes the Lite database monthly.
        CronTask::register(
            self::class,
            'updatedb',
            30 * DAY_TIMESTAMP,
            [
                'comment' => __('Download the monthly DB-IP Lite country database', 'moresecurity'),
                'mode'    => CronTask::MODE_EXTERNAL,
                'hourmin' => 3,
                'hourmax' => 4,
            ],
        );
    }

    public static function uninstall(Migration $migration): void
    {
        self::removeFile(self::getDatabasePath());
    }
}
