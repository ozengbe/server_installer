<?php
// DomainPilot isolation probe. Executed through a tenant's own PHP-FPM, so it
// runs inside the real sandbox. Every check reports whether an action was
// possible; the caller decides which outcomes are acceptable.
//   Params: DP_SELF=<tenant>, DP_OTHERS=<t2,t3>, DP_OTHER_DB=<db>
// Read-only towards other tenants: it only tries to read, list or connect.

header('Content-Type: application/json');
error_reporting(0);
set_time_limit(60);

$self = $_SERVER['DP_SELF'] ?? '';
$others = array_filter(explode(',', $_SERVER['DP_OTHERS'] ?? ''));
$otherDb = $_SERVER['DP_OTHER_DB'] ?? '';
$root = "/srv/tenants/$self";
$r = [];

function tcp($host, $port, $timeout = 2.0) {
    $s = @fsockopen($host, $port, $errno, $errstr, $timeout);
    if ($s) { fclose($s); return true; }
    return false;
}
function unix_connect($path) {
    $s = @stream_socket_client("unix://$path", $errno, $errstr, 2);
    if ($s) { fclose($s); return true; }
    return false;
}

// --- identity & sandbox ---------------------------------------------------
$r['euid'] = function_exists('posix_geteuid') ? posix_geteuid() : -1;
$status = @file_get_contents('/proc/self/status') ?: '';
$r['no_new_privs'] = (bool) preg_match('/^NoNewPrivs:\s+1/m', $status);
$r['seccomp_filter'] = (bool) preg_match('/^Seccomp:\s+2/m', $status);
$r['cap_eff_zero'] = (bool) preg_match('/^CapEff:\s+0+$/m', $status);
$r['apparmor_label'] = trim(@file_get_contents('/proc/self/attr/current') ?: '');

// --- own tree (positive controls and code immutability) -------------------
$r['own_read_code'] = is_readable("$root/app/public/" . basename(__FILE__));
$r['own_write_code'] = @file_put_contents("$root/app/public/dp-probe-write.txt", 'x') !== false;
@unlink("$root/app/public/dp-probe-write.txt");
$r['own_write_data'] = @file_put_contents("$root/data/dp-probe.txt", 'x') !== false;
@unlink("$root/data/dp-probe.txt");
$r['own_write_tmp'] = @file_put_contents(sys_get_temp_dir() . '/dp-probe.txt', 'x') !== false;
$r['own_config_readable'] = is_readable("/etc/domainpilot/tenants/$self/php-fpm.conf");

// --- other tenants: files, configs, secrets, sockets ----------------------
$listing = @scandir('/srv/tenants') ?: [];
$r['srv_tenants_listing'] = array_values(array_diff($listing, ['.', '..']));
$r['other_paths_visible'] = [];
$r['other_sockets_connectable'] = [];
foreach ($others as $o) {
    foreach (["/srv/tenants/$o", "/srv/tenants/$o/app/public", "/etc/domainpilot/tenants/$o",
              "/etc/domainpilot/tenants/$o/secrets/db.env", "/var/log/domainpilot/tenants/$o",
              "/run/domainpilot/$o", "/var/lib/domainpilot/cache/$o"] as $p) {
        if (@file_exists($p) || @is_readable($p)) { $r['other_paths_visible'][] = $p; }
    }
    foreach (["/run/domainpilot/$o/php/php.sock", "/run/domainpilot/$o/cache/cache.sock"] as $s) {
        if (unix_connect($s)) { $r['other_sockets_connectable'][] = $s; }
    }
}

// --- host secrets and control plane -------------------------------------
$r['host_secret_paths_readable'] = [];
foreach (['/etc/shadow', '/etc/domainpilot/install.yml', '/var/lib/domainpilot/registry.sqlite3',
          '/root', '/etc/ssh/ssh_host_ed25519_key', '/etc/nginx/domainpilot/default-tls/key.pem',
          '/var/log/domainpilot/audit.jsonl'] as $p) {
    if (@is_readable($p)) { $r['host_secret_paths_readable'][] = $p; }
}

// --- processes: only our own should be visible ----------------------------
$foreign = 0;
foreach (glob('/proc/[0-9]*') ?: [] as $d) {
    $st = @stat($d);
    if ($st && $st['uid'] !== $r['euid']) { $foreign++; }
}
$r['foreign_processes_visible'] = $foreign;

// --- dangerous functions --------------------------------------------------
$r['exec_functions_available'] = array_values(array_filter(
    ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec'],
    'function_exists'));

// --- network ---------------------------------------------------------------
$r['net'] = [
    'loopback_ssh_v4'      => tcp('127.0.0.1', 22),
    'loopback_http_v4'     => tcp('127.0.0.1', 80),
    'loopback_ssh_v6'      => tcp('[::1]', 22),
    'cloud_metadata'       => tcp('169.254.169.254', 80, 1.0),
    'private_10'           => tcp('10.0.0.1', 80, 1.0),
    'private_192_168'      => tcp('192.168.0.1', 80, 1.0),
    'public_dns_tcp'       => tcp('1.1.1.1', 53, 2.0),
    'public_https'         => tcp('1.1.1.1', 443, 3.0),
];
$r['dns_resolves'] = gethostbyname('nginx.org') !== 'nginx.org';

// --- database ----------------------------------------------------------------
$r['db_own_login'] = false;
$r['db_other_access'] = false;
$r['db_global_privs'] = null;
if (class_exists('mysqli')) {
    mysqli_report(MYSQLI_REPORT_OFF);
    $db = @new mysqli('localhost', $self, '', '', 0, '/run/mysqld/mysqld.sock');
    if ($db && !$db->connect_errno) {
        $r['db_own_login'] = true;
        if ($otherDb !== '') {
            $r['db_other_access'] = @$db->select_db($otherDb) === true;
        }
        $res = @$db->query('SHOW GRANTS');
        $grants = [];
        while ($res && ($row = $res->fetch_row())) { $grants[] = $row[0]; }
        $r['db_global_privs'] = (bool) preg_grep('/ON \*\.\*/', preg_grep('/GRANT USAGE/', $grants, PREG_GREP_INVERT));
        $db->close();
    }
}

// --- own cache --------------------------------------------------------------
$r['cache_own_ping'] = false;
$cs = @stream_socket_client("unix:///run/domainpilot/$self/cache/cache.sock", $e1, $e2, 2);
if ($cs) {
    fwrite($cs, "PING\r\n");
    $r['cache_own_ping'] = trim((string) fgets($cs)) === '+PONG';
    fwrite($cs, "CONFIG GET maxmemory\r\n");
    $r['cache_config_allowed'] = strpos((string) fgets($cs), '-') !== 0;
    fclose($cs);
}

// --- limits -----------------------------------------------------------------
$r['memory_limit'] = ini_get('memory_limit');
$r['open_basedir'] = ini_get('open_basedir');

echo json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
