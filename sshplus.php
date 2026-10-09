<?php
// ============================================================
// SSHPLUS MANAGER - Panel Web PHP - Version Final
// ============================================================

define('SESSION_NAME', 'sshplus_panel');
define('SECRET_FILE', '/etc/sshplus-panel/.secret');

session_name(SESSION_NAME);
session_start();

// Cargar contraseña hasheada desde archivo externo
function loadPasswordHash() {
    if (!file_exists(SECRET_FILE)) {
        // Primera vez: crear carpeta y hash por defecto
        @mkdir('/etc/sshplus-panel', 0700, true);
        $hash = password_hash('admin123', PASSWORD_BCRYPT);
        file_put_contents(SECRET_FILE, $hash);
        chmod(SECRET_FILE, 0600);
    }
    return trim(file_get_contents(SECRET_FILE));
}

// --- ENDPOINTS SIN AUTH ---
if (isset($_GET['online'])) {
    header('Content-Type: application/json');
    $n = trim(shell_exec('curl -s http://127.0.0.1:8888/server/online 2>/dev/null'));
    echo json_encode(['online' => intval($n)]);
    exit;
}

if (isset($_GET['monitor'])) {
    header('Content-Type: application/json');
    $cpu       = trim(shell_exec("top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'"));
    $mem_total = intval(trim(shell_exec("grep MemTotal /proc/meminfo | awk '{print $2}'")));
    $mem_free  = intval(trim(shell_exec("grep MemAvailable /proc/meminfo | awk '{print $2}'")));
    $mem_used  = round(($mem_total - $mem_free) / $mem_total * 100, 1);
    $disk      = trim(shell_exec("df -h / | awk 'NR==2{print $5}'"));
    $disk_used = intval($disk);
    $uptime    = trim(shell_exec("uptime -p 2>/dev/null || uptime | awk -F'up ' '{print $2}' | cut -d',' -f1"));
    echo json_encode(['cpu'=>floatval($cpu),'mem_used'=>$mem_used,'disk'=>$disk_used,'uptime'=>$uptime]);
    exit;
}

if (isset($_GET['token_info'])) {
    header('Content-Type: application/json');
    $token = trim(@file_get_contents('/etc/SSHPlus/Token.txt') ?: 'No configurado');
    $ip    = trim(shell_exec("curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print \$1}'"));
    echo json_encode(['ok'=>true,'token'=>$token,'ip'=>$ip]);
    exit;
}

// --- LOGIN ---
if (isset($_POST['login_pass'])) {
    $hash = loadPasswordHash();
    if (password_verify($_POST['login_pass'], $hash)) {
        $_SESSION['auth'] = true;
    } else {
        $login_error = 'Contraseña incorrecta';
    }
}

// Cambiar contraseña desde panel
if (isset($_POST['change_panel_pass']) && !empty($_SESSION['auth'])) {
    $current = $_POST['current_pass'];
    $new1    = $_POST['new_pass'];
    $new2    = $_POST['new_pass2'];
    $hash    = loadPasswordHash();
    if (!password_verify($current, $hash)) {
        $pass_error = 'Contraseña actual incorrecta';
    } elseif (strlen($new1) < 6) {
        $pass_error = 'La nueva contraseña debe tener al menos 6 caracteres';
    } elseif ($new1 !== $new2) {
        $pass_error = 'Las contraseñas no coinciden';
    } else {
        $newHash = password_hash($new1, PASSWORD_BCRYPT);
        file_put_contents(SECRET_FILE, $newHash);
        chmod(SECRET_FILE, 0600);
        $pass_success = 'Contraseña actualizada correctamente';
    }
}
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ?');
    exit;
}
$auth = !empty($_SESSION['auth']);

// --- API ACTIONS ---
if ($auth && isset($_POST['action'])) {
    header('Content-Type: application/json');
    $action = $_POST['action'];

    if ($action === 'list') {
        echo json_encode(getUsers());
        exit;
    }

    if ($action === 'create') {
        $user  = preg_replace('/[^a-z0-9_]/', '', strtolower($_POST['username']));
        $pass  = $_POST['password'];
        $days  = intval($_POST['days']);
        $limit = intval($_POST['limit']);
        if (empty($user) || empty($pass) || $days < 1 || $limit < 1) {
            echo json_encode(['ok'=>false,'msg'=>'Datos incompletos']);
            exit;
        }
        shell_exec("sudo useradd -M -s /bin/false $user 2>&1");
        shell_exec("echo '$user:$pass' | sudo /usr/sbin/chpasswd 2>&1");
        shell_exec("sudo chage -E \$(date -d '+{$days} days' +%Y-%m-%d) $user 2>&1");
        file_put_contents("/etc/SSHPlus/senha/$user", $pass);
        saveLimitConn($user, $limit);
        echo json_encode(['ok'=>true,'msg'=>"Usuario $user creado correctamente"]);
        exit;
    }

    if ($action === 'create_token') {
        $user  = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $days  = intval($_POST['days']);
        $limit = intval($_POST['limit']);
        $pass  = trim(@file_get_contents('/etc/SSHPlus/Token.txt') ?: '');
        $ip    = trim(shell_exec("curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print \$1}'"));
        if (empty($user) || empty($pass) || $days < 1 || $limit < 1) {
            echo json_encode(['ok'=>false,'msg'=>'Datos incompletos o Token.txt no encontrado']);
            exit;
        }
        shell_exec("sudo useradd -M -s /bin/false $user 2>&1");
        shell_exec("echo '$user:$pass' | sudo /usr/sbin/chpasswd 2>&1");
        shell_exec("sudo chage -E \$(date -d '+{$days} days' +%Y-%m-%d) $user 2>&1");
        file_put_contents("/etc/SSHPlus/senha/$user", $pass);
        saveLimitConn($user, $limit);
        $expiry = date('d/m/Y', strtotime("+{$days} days"));
        echo json_encode(['ok'=>true,'msg'=>"Token $user creado",'token'=>$user,'ip'=>$ip,'expiry'=>$expiry,'limit'=>$limit]);
        exit;
    }

    if ($action === 'delete') {
        $user = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        shell_exec("sudo userdel -r $user 2>&1");
        @unlink("/etc/SSHPlus/senha/$user");
        deleteLimitConn($user);
        echo json_encode(['ok'=>true,'msg'=>"Usuario $user eliminado"]);
        exit;
    }

    if ($action === 'delete_expired') {
        $users   = getUsers();
        $expired = array_filter($users, fn($u) => $u['status'] === 'expired');
        $count   = 0;
        foreach ($expired as $u) {
            $name = $u['username'];
            shell_exec("sudo userdel -r $name 2>&1");
            @unlink("/etc/SSHPlus/senha/$name");
            deleteLimitConn($name);
            $count++;
        }
        echo json_encode(['ok'=>true,'msg'=>"$count usuarios expirados eliminados"]);
        exit;
    }

    if ($action === 'check_online') {
        $user  = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $count = intval(trim(shell_exec("ps aux | grep 'sshd: $user' | grep -v grep | grep -v priv | wc -l") ?: '0'));
        echo json_encode(['ok'=>true,'online'=>$count > 0,'connections'=>$count]);
        exit;
    }

    if ($action === 'change_pass') {
        $user = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $pass = $_POST['password'];
        shell_exec("echo '$user:$pass' | sudo /usr/sbin/chpasswd 2>&1");
        file_put_contents("/etc/SSHPlus/senha/$user", $pass);
        echo json_encode(['ok'=>true,'msg'=>"Contraseña actualizada"]);
        exit;
    }

    if ($action === 'change_expiry') {
        $user = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $days = intval($_POST['days']);
        shell_exec("sudo chage -E \$(date -d '+{$days} days' +%Y-%m-%d) $user 2>&1");
        echo json_encode(['ok'=>true,'msg'=>"Expiración actualizada"]);
        exit;
    }

    if ($action === 'change_limit') {
        $user  = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $limit = intval($_POST['limit']);
        saveLimitConn($user, $limit);
        echo json_encode(['ok'=>true,'msg'=>"Límite actualizado"]);
        exit;
    }

    echo json_encode(['ok'=>false,'msg'=>'Acción desconocida']);
    exit;
}

// --- FUNCIONES ---
function getUsers() {
    $system_users = ['root','daemon','bin','sys','sync','games','man','lp','mail',
                     'news','uucp','proxy','www-data','backup','list','irc','gnats',
                     'nobody','systemd-network','systemd-resolve','syslog','messagebus',
                     'uuidd','dnsmasq','usbmux','rtkit','cups-pk-helper','speech-dispatcher',
                     'avahi','kernoops','saned','whoopsie','colord','hplip','pulse','gdm',
                     'snap_daemon','lxd','nm-applet'];
    $users  = [];
    $passwd = file('/etc/passwd', FILE_IGNORE_NEW_LINES);
    foreach ($passwd as $line) {
        $parts = explode(':', $line);
        if (count($parts) < 7) continue;
        $username = $parts[0];
        $uid      = intval($parts[2]);
        $shell    = $parts[6];
        if ($uid < 1000) continue;
        if (in_array($username, $system_users)) continue;
        if (!in_array($shell, ['/bin/false','/bin/bash','/bin/sh','/usr/sbin/nologin'])) continue;
        $chage     = shell_exec("sudo chage -l $username 2>/dev/null");
        $expiry    = 'Nunca';
        $days_left = 9999;
        if (preg_match('/Account expires\s*:\s*(.+)/i', $chage, $m)) {
            $exp = trim($m[1]);
            if (strtolower($exp) !== 'never') {
                $expiry    = date('Y-m-d', strtotime($exp));
                $days_left = (int)ceil((strtotime($expiry) - time()) / 86400);
            }
        }
        $conn_active = intval(trim(shell_exec("ps aux | grep 'sshd: $username' | grep -v grep | grep -v priv | wc -l") ?: '0'));
        $conn_limit  = getLimitConn($username);
        $status      = ($days_left < 0) ? 'expired' : 'active';
        $users[] = [
            'username'    => $username,
            'status'      => $status,
            'expiry'      => $expiry,
            'days_left'   => $days_left === 9999 ? '∞' : $days_left,
            'conn_active' => $conn_active,
            'conn_limit'  => $conn_limit,
        ];
    }
    return $users;
}

function getLimitConn($user) {
    $file = '/etc/SSHPlus/usuarios.db';
    if (!file_exists($file)) return 1;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if ($parts[0] === $user) return intval($parts[1]);
    }
    return 1;
}

function saveLimitConn($user, $limit) {
    $file  = '/etc/SSHPlus/usuarios.db';
    $lines = file_exists($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    $found = false;
    foreach ($lines as &$line) {
        $parts = preg_split('/\s+/', trim($line));
        if ($parts[0] === $user) { $line = "$user $limit"; $found = true; break; }
    }
    if (!$found) $lines[] = "$user $limit";
    file_put_contents($file, implode("\n", $lines) . "\n");
}

function deleteLimitConn($user) {
    $file = '/etc/SSHPlus/usuarios.db';
    if (!file_exists($file)) return;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $lines = array_filter($lines, function($l) use ($user) {
        $parts = preg_split('/\s+/', trim($l));
        return $parts[0] !== $user;
    });
    file_put_contents($file, implode("\n", $lines) . "\n");
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSHPLUS Manager</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#060b14;font-family:'Share Tech Mono',monospace;color:#e0f0ff;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px);pointer-events:none;z-index:999}
.grid-bg{position:fixed;inset:0;background-image:linear-gradient(rgba(0,200,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}
.wrap{max-width:1200px;margin:0 auto;padding:0 20px}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:#0d1321;border:1px solid #1e3a5f;border-radius:16px;padding:48px 40px;width:360px;text-align:center;box-shadow:0 0 60px rgba(0,180,255,0.15)}
.login-title{font-family:'Orbitron',monospace;font-size:24px;font-weight:900;letter-spacing:3px;background:linear-gradient(90deg,#00c8ff,#7eb8ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.login-title span{-webkit-text-fill-color:#00ff9d}
.login-sub{color:#3a7ca5;font-size:11px;letter-spacing:2px;margin-bottom:32px}
.login-input{width:100%;background:#0a0f1a;border:1px solid #1e3a5f;border-radius:8px;padding:12px 16px;color:#e0f0ff;font-family:monospace;font-size:14px;outline:none;margin-bottom:16px;transition:border-color .2s}
.login-input:focus{border-color:#00c8ff}
.login-btn{width:100%;background:transparent;border:1px solid #00ff9d;color:#00ff9d;border-radius:8px;padding:12px;cursor:pointer;font-family:monospace;font-size:13px;letter-spacing:1px;transition:all .2s}
.login-btn:hover{background:#00ff9d;color:#0a0f1a}
.login-err{color:#ff4d6d;font-size:12px;margin-top:8px}
.header{padding:28px 0 20px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #0e2a45;flex-wrap:wrap;gap:12px}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,#00c8ff,#0066ff);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 20px rgba(0,200,255,0.4)}
.logo-text{font-family:'Orbitron',monospace;font-size:20px;font-weight:900;letter-spacing:3px;background:linear-gradient(90deg,#00c8ff,#7eb8ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-text span{-webkit-text-fill-color:#00ff9d}
.logo-sub{color:#3a7ca5;font-size:10px;margin-top:3px;letter-spacing:2px}
.header-right{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}
.stat-card{background:linear-gradient(135deg,#0d1321,#0a1525);border:1px solid #1e3a5f;border-radius:14px;padding:18px 20px;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;width:100%;height:2px}
.stat-card:nth-child(1)::before{background:linear-gradient(90deg,transparent,#00c8ff,transparent)}
.stat-card:nth-child(2)::before{background:linear-gradient(90deg,transparent,#00ff9d,transparent)}
.stat-card:nth-child(3)::before{background:linear-gradient(90deg,transparent,#ff4d6d,transparent)}
.stat-card:nth-child(4)::before{background:linear-gradient(90deg,transparent,#ffbe0b,transparent)}
.stat-label{color:#3a7ca5;font-size:10px;letter-spacing:2px;margin-bottom:6px}
.stat-value{font-family:'Orbitron',monospace;font-weight:700;font-size:30px}
.stat-card:nth-child(1) .stat-value{color:#00c8ff;text-shadow:0 0 20px #00c8ff66}
.stat-card:nth-child(2) .stat-value{color:#00ff9d;text-shadow:0 0 20px #00ff9d66}
.stat-card:nth-child(3) .stat-value{color:#ff4d6d;text-shadow:0 0 20px #ff4d6d66}
.stat-card:nth-child(4) .stat-value{color:#ffbe0b;text-shadow:0 0 20px #ffbe0b66}
.monitor{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px}
.mon-card{background:#0d1321;border:1px solid #1e3a5f;border-radius:14px;padding:16px 20px}
.mon-label{color:#3a7ca5;font-size:10px;letter-spacing:2px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
.mon-pct{font-family:'Orbitron',monospace;font-size:20px;font-weight:700}
.mon-bar{background:#0a0f1a;border-radius:4px;height:8px;margin-top:8px;overflow:hidden}
.mon-inner{height:100%;border-radius:4px;transition:width 1s ease}
.mon-cpu .mon-inner{background:#00c8ff;box-shadow:0 0 8px #00c8ff}
.mon-ram .mon-inner{background:#00ff9d;box-shadow:0 0 8px #00ff9d}
.mon-disk .mon-inner{background:#ffbe0b;box-shadow:0 0 8px #ffbe0b}
.mon-warn{background:#ff4d6d!important;box-shadow:0 0 8px #ff4d6d!important}
.uptime-val{color:#7eb8ff;font-size:12px;margin-top:6px}
.toolbar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.search-input{background:#0d1321;border:1px solid #1e3a5f;border-radius:10px;padding:10px 14px;color:#e0f0ff;font-family:monospace;font-size:13px;outline:none;flex:1;min-width:180px;transition:border-color .2s}
.search-input:focus{border-color:#00c8ff}
.filter-btn{background:transparent;border:1px solid #1e3a5f;color:#3a7ca5;border-radius:10px;padding:10px 14px;cursor:pointer;font-family:monospace;font-size:11px;letter-spacing:1px;transition:all .2s}
.filter-btn.active{background:#00c8ff22;border-color:#00c8ff;color:#00c8ff}
.btn-del-exp{background:transparent;border:1px solid #ff4d6d55;color:#ff4d6d;border-radius:10px;padding:10px 14px;cursor:pointer;font-family:monospace;font-size:11px;letter-spacing:1px;transition:all .2s}
.btn-del-exp:hover{background:rgba(255,77,109,0.15)}
.table-wrap{background:#0d1321;border:1px solid #1e3a5f;border-radius:16px;overflow:hidden;margin-bottom:40px}
.tbl{width:100%;border-collapse:collapse}
.tbl th{padding:13px 16px;text-align:left;color:#3a7ca5;font-size:10px;letter-spacing:2px;font-weight:400;border-bottom:1px solid #1e3a5f}
.tbl td{padding:13px 16px;border-bottom:1px solid #0e2a45;transition:background .15s;vertical-align:middle}
.tbl tr:hover td{background:rgba(0,200,255,0.04)}
.tbl tr:last-child td{border-bottom:none}
.badge{display:inline-flex;align-items:center;gap:5px;border-radius:20px;padding:3px 10px;font-size:10px;letter-spacing:1px}
.badge-active{background:rgba(0,255,157,0.1);border:1px solid rgba(0,255,157,0.3);color:#00ff9d}
.badge-expired{background:rgba(255,77,109,0.1);border:1px solid rgba(255,77,109,0.3);color:#ff4d6d}
.dot{width:5px;height:5px;border-radius:50%;display:inline-block}
.dot-active{background:#00ff9d;box-shadow:0 0 5px #00ff9d;animation:pulse 2s infinite}
.dot-expired{background:#ff4d6d}
.expiry-ok{color:#00ff9d;font-size:12px}
.expiry-warn{color:#ffbe0b;font-size:12px}
.expiry-bad{color:#ff4d6d;font-size:12px}
.conn-text{font-size:12px;margin-bottom:4px}
.bar-wrap{background:#0a0f1a;border-radius:3px;height:5px;overflow:hidden}
.bar-inner{height:100%;border-radius:3px;transition:width .5s}
.bar-blue{background:#00c8ff;box-shadow:0 0 6px #00c8ff}
.bar-red{background:#ff4d6d;box-shadow:0 0 6px #ff4d6d}
.action-btn{background:none;border:1px solid #1e3a5f;color:#7eb8ff;border-radius:6px;padding:5px 10px;cursor:pointer;font-size:11px;font-family:monospace;transition:all .2s;margin-right:4px}
.action-btn:hover{border-color:#00c8ff;color:#00c8ff}
.check-btn{background:none;border:1px solid #ffbe0b44;color:#ffbe0b;border-radius:6px;padding:5px 10px;cursor:pointer;font-size:11px;font-family:monospace;transition:all .2s;margin-right:4px}
.check-btn:hover{background:rgba(255,190,11,0.1)}
.del-btn{background:none;border:1px solid rgba(255,77,109,0.3);color:#ff4d6d;border-radius:6px;padding:5px 10px;cursor:pointer;font-size:11px;font-family:monospace;transition:all .2s}
.del-btn:hover{background:rgba(255,77,109,0.15)}
.online-tag{display:inline-block;background:#00ff9d22;border:1px solid #00ff9d44;color:#00ff9d;border-radius:4px;padding:2px 8px;font-size:10px;margin-left:6px;animation:pulse 2s infinite}
.offline-tag{display:inline-block;background:#aaa1;border:1px solid #aaa3;color:#aaa;border-radius:4px;padding:2px 8px;font-size:10px;margin-left:6px}
.empty{padding:40px;text-align:center;color:#3a7ca5}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.8);backdrop-filter:blur(6px);z-index:1000;align-items:center;justify-content:center}
.overlay.show{display:flex}
.modal{background:#0d1321;border:1px solid #1e3a5f;border-radius:16px;padding:28px;width:90%;max-width:460px;box-shadow:0 0 60px rgba(0,180,255,0.15);animation:fadeIn .2s ease}
.modal-title{color:#00c8ff;font-family:'Orbitron',monospace;font-size:14px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center}
.close-btn{background:none;border:none;color:#aaa;cursor:pointer;font-size:18px}
.field{margin-bottom:14px}
.field label{display:block;color:#7ec8e3;font-size:10px;letter-spacing:1px;margin-bottom:5px}
.field input,.field select{width:100%;background:#0a0f1a;border:1px solid #1e3a5f;border-radius:7px;padding:9px 12px;color:#e0f0ff;font-family:monospace;font-size:13px;outline:none;transition:border-color .2s}
.field input:focus,.field select:focus{border-color:#00c8ff}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.btn{border-radius:7px;padding:9px 18px;cursor:pointer;font-family:monospace;font-size:12px;letter-spacing:1px;transition:all .2s;border:1px solid;width:100%}
.btn-green{background:transparent;border-color:#00ff9d;color:#00ff9d}
.btn-green:hover{background:#00ff9d;color:#0a0f1a}
.btn-yellow{background:transparent;border-color:#ffbe0b;color:#ffbe0b}
.btn-yellow:hover{background:#ffbe0b;color:#0a0f1a}
.btn-cancel{background:transparent;border-color:#1e3a5f;color:#aaa}
.btn-cancel:hover{border-color:#aaa;color:#e0f0ff}
.btn-danger{background:#ff4d6d;border-color:#ff4d6d;color:#fff}
.btn-danger:hover{background:#c9003a}
.btn-new{background:transparent;border:1px solid #00ff9d;color:#00ff9d;border-radius:8px;padding:10px 20px;cursor:pointer;font-family:monospace;font-size:12px;letter-spacing:1px;transition:all .2s}
.btn-new:hover{background:#00ff9d;color:#0a0f1a}
.btn-token{background:transparent;border:1px solid #ffbe0b;color:#ffbe0b;border-radius:8px;padding:10px 20px;cursor:pointer;font-family:monospace;font-size:12px;letter-spacing:1px;transition:all .2s}
.btn-token:hover{background:#ffbe0b;color:#0a0f1a}
.btn-refresh{background:transparent;border:1px solid #1e3a5f;color:#3a7ca5;border-radius:8px;padding:10px 16px;cursor:pointer;font-family:monospace;font-size:12px;transition:all .2s}
.btn-refresh:hover{border-color:#00c8ff;color:#00c8ff}
.btn-logout{background:transparent;border:1px solid #ff4d6d33;color:#ff4d6d;border-radius:8px;padding:10px 16px;cursor:pointer;font-family:monospace;font-size:12px;transition:all .2s;text-decoration:none}
.btn-logout:hover{background:rgba(255,77,109,0.1)}
.modal-actions{display:flex;gap:10px;margin-top:8px}
.danger-msg{color:#ff4d6d;text-align:center;margin:8px 0 20px;font-size:13px;line-height:1.8}
.danger-msg strong{color:#fff}
.result-box{background:#0a0f1a;border:1px solid #1e3a5f;border-radius:10px;padding:16px;font-family:monospace;font-size:13px;line-height:2.2;margin-bottom:16px}
.toast{position:fixed;bottom:28px;right:28px;border-radius:10px;padding:12px 20px;font-size:12px;font-family:monospace;z-index:2000;display:none;animation:fadeIn .3s ease}
.toast.show{display:block}
.toast-ok{background:#0a1a0f;border:1px solid #00ff9d;color:#00ff9d;box-shadow:0 0 20px #00ff9d33}
.toast-err{background:#1a0a0f;border:1px solid #ff4d6d;color:#ff4d6d;box-shadow:0 0 20px #ff4d6d33}
.loading{text-align:center;padding:40px;color:#3a7ca5;font-size:13px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:#060b14}::-webkit-scrollbar-thumb{background:#1e3a5f;border-radius:3px}
@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}.monitor{grid-template-columns:1fr}.header{flex-direction:column}}
</style>
</head>
<body>
<div class="grid-bg"></div>

<?php if (!$auth): ?>
<div class="login-wrap">
  <div class="login-box">
    <div class="login-title">SSH<span>PLUS</span></div>
    <div class="login-sub">PANEL DE GESTIÓN</div>
    <form method="POST">
      <input class="login-input" type="password" name="login_pass" placeholder="Contraseña del panel" autofocus>
      <button class="login-btn" type="submit">INGRESAR</button>
      <?php if (!empty($pass_success ?? '')): ?>
        <div style="color:#00ff9d;font-size:12px;margin-top:8px">✓ <?= htmlspecialchars($pass_success) ?></div>
      <?php endif; ?>
      <?php if (!empty($login_error)): ?>
        <div class="login-err">⚠ <?= htmlspecialchars($login_error) ?></div>
      <?php endif; ?>
    </form>
  </div>
</div>

<?php else: ?>
<div class="wrap">
  <div class="header">
    <div>
      <div class="logo">
        <div class="logo-icon">⚡</div>
        <div>
          <div class="logo-text">SSH<span>PLUS</span></div>
          <div class="logo-sub">PANEL DE GESTIÓN DE USUARIOS</div>
        </div>
      </div>
    </div>
    <div class="header-right">
      <button class="btn-refresh" onclick="loadUsers()">↻ Actualizar</button>
      <button class="btn-token" onclick="openTokenModal()">⚡ TOKEN</button>
      <button class="btn-new" onclick="openModal('modal-create')">+ NUEVO USUARIO</button>
      <button class="btn-refresh" onclick="openModal('modal-chpass')" style="border-color:#7eb8ff;color:#7eb8ff">🔑 Contraseña</button>
      <a href="?logout" class="btn-logout">Salir</a>
    </div>
  </div>

  <div class="stats">
    <div class="stat-card"><div class="stat-label">TOTAL USUARIOS</div><div class="stat-value" id="s-total">—</div></div>
    <div class="stat-card"><div class="stat-label">ACTIVOS</div><div class="stat-value" id="s-active">—</div></div>
    <div class="stat-card"><div class="stat-label">EXPIRADOS</div><div class="stat-value" id="s-expired">—</div></div>
    <div class="stat-card"><div class="stat-label">ONLINE AHORA</div><div class="stat-value" id="s-conn">—</div></div>
  </div>

  <div class="monitor">
    <div class="mon-card mon-cpu">
      <div class="mon-label">CPU <span class="mon-pct" id="m-cpu">—%</span></div>
      <div class="mon-bar"><div class="mon-inner" id="m-cpu-bar" style="width:0%"></div></div>
    </div>
    <div class="mon-card mon-ram">
      <div class="mon-label">RAM <span class="mon-pct" id="m-ram">—%</span></div>
      <div class="mon-bar"><div class="mon-inner" id="m-ram-bar" style="width:0%"></div></div>
      <div class="uptime-val" id="m-uptime"></div>
    </div>
    <div class="mon-card mon-disk">
      <div class="mon-label">DISCO <span class="mon-pct" id="m-disk">—%</span></div>
      <div class="mon-bar"><div class="mon-inner" id="m-disk-bar" style="width:0%"></div></div>
    </div>
  </div>

  <div class="toolbar">
    <input class="search-input" id="search" placeholder="🔍  Buscar usuario..." oninput="renderTable()">
    <button class="filter-btn active" onclick="setFilter('all',this)">TODOS</button>
    <button class="filter-btn" onclick="setFilter('active',this)">ACTIVOS</button>
    <button class="filter-btn" onclick="setFilter('expired',this)">EXPIRADOS</button>
    <button class="btn-del-exp" onclick="confirmDeleteExpired()">🗑 Limpiar expirados</button>
  </div>

  <div class="table-wrap">
    <div style="overflow-x:auto">
      <table class="tbl">
        <thead>
          <tr><th>USUARIO</th><th>ESTADO</th><th>CONEXIONES</th><th>EXPIRACIÓN</th><th>DÍAS REST.</th><th>ACCIONES</th></tr>
        </thead>
        <tbody id="tbody"><tr><td colspan="6" class="loading">⟳ Cargando...</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<!-- CREATE MODAL -->
<div class="overlay" id="modal-create">
  <div class="modal">
    <div class="modal-title">// CREAR USUARIO <button class="close-btn" onclick="closeModal('modal-create')">✕</button></div>
    <div class="field"><label>NOMBRE DE USUARIO</label><input id="c-user" placeholder="ej: cliente01"></div>
    <div class="field"><label>CONTRASEÑA</label><input id="c-pass" type="password" placeholder="Contraseña segura"></div>
    <div class="field-row">
      <div class="field"><label>DÍAS DE VALIDEZ</label><input id="c-days" type="number" value="30" min="1"></div>
      <div class="field"><label>LÍMITE CONEXIONES</label><input id="c-limit" type="number" value="3" min="1" max="100"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-green" onclick="createUser()">✓ CREAR</button>
      <button class="btn btn-cancel" onclick="closeModal('modal-create')">CANCELAR</button>
    </div>
  </div>
</div>

<!-- TOKEN MODAL -->
<div class="overlay" id="modal-token">
  <div class="modal">
    <div class="modal-title" style="color:#ffbe0b">// CREAR CON TOKEN <button class="close-btn" onclick="closeModal('modal-token')">✕</button></div>
    <!-- FORM -->
    <div id="token-form">
      <div style="background:#0a1525;border:1px solid #ffbe0b33;border-radius:8px;padding:12px 16px;margin-bottom:16px">
        <div style="color:#3a7ca5;font-size:10px;letter-spacing:1px;margin-bottom:4px">TOKEN GENERAL (contraseña automática)</div>
        <div style="display:flex;align-items:center;gap:10px">
          <span id="token-val" style="color:#ffbe0b;font-family:monospace;font-size:14px;letter-spacing:2px;flex:1">—</span>
          <button onclick="copyToken()" style="background:none;border:1px solid #ffbe0b44;color:#ffbe0b;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:11px;font-family:monospace">⎘</button>
        </div>
      </div>
      <div class="field"><label>TOKEN ID (pegado desde la app del cliente)</label><input id="t-user" placeholder="ej: 0706eac8cedd8bae"></div>
      <div class="field-row">
        <div class="field"><label>DÍAS DE VALIDEZ</label><input id="t-days" type="number" value="30" min="1"></div>
        <div class="field"><label>LÍMITE CONEXIONES</label><input id="t-limit" type="number" value="3" min="1" max="100"></div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-yellow" onclick="createTokenUser()">✓ CREAR</button>
        <button class="btn btn-cancel" onclick="closeModal('modal-token')">CANCELAR</button>
      </div>
    </div>
    <!-- RESULTADO -->
    <div id="token-result" style="display:none">
      <div style="text-align:center;color:#00ff9d;font-size:16px;margin-bottom:16px">✓ CUENTA SSH CREADA</div>
      <div class="result-box">
        <div><span style="color:#3a7ca5">IP: </span><span style="color:#00c8ff" id="r-ip">—</span></div>
        <div><span style="color:#3a7ca5">Token: </span><span style="color:#ffbe0b" id="r-token">—</span></div>
        <div><span style="color:#3a7ca5">Expira em: </span><span style="color:#00ff9d" id="r-expiry">—</span></div>
        <div><span style="color:#3a7ca5">Límite de conexión: </span><span style="color:#00ff9d" id="r-limit">—</span></div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-green" onclick="copyResult()">⎘ COPIAR</button>
        <button class="btn btn-cancel" onclick="resetTokenModal()">NUEVO</button>
      </div>
    </div>
  </div>
</div>

<!-- EDIT MODAL -->
<div class="overlay" id="modal-edit">
  <div class="modal">
    <div class="modal-title">// EDITAR: <span id="e-title"></span> <button class="close-btn" onclick="closeModal('modal-edit')">✕</button></div>
    <input type="hidden" id="e-user">
    <div class="field"><label>NUEVA CONTRASEÑA (vacío = sin cambio)</label><input id="e-pass" type="password" placeholder="Nueva contraseña"></div>
    <div class="field-row">
      <div class="field"><label>EXTENDER DÍAS</label><input id="e-days" type="number" value="30" min="1"></div>
      <div class="field"><label>LÍMITE CONEXIONES</label><input id="e-limit" type="number" value="3" min="1" max="100"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-green" onclick="saveEdit()">✓ GUARDAR</button>
      <button class="btn btn-cancel" onclick="closeModal('modal-edit')">CANCELAR</button>
    </div>
  </div>
</div>

<!-- DELETE MODAL -->
<div class="overlay" id="modal-del">
  <div class="modal">
    <div class="modal-title">// ELIMINAR USUARIO <button class="close-btn" onclick="closeModal('modal-del')">✕</button></div>
    <input type="hidden" id="d-user">
    <p class="danger-msg">¿Eliminar al usuario <strong id="d-name"></strong>?<br><span style="color:#3a7ca5;font-size:11px">Esta acción no se puede deshacer.</span></p>
    <div class="modal-actions">
      <button class="btn btn-danger" onclick="deleteUser()">✕ ELIMINAR</button>
      <button class="btn btn-cancel" onclick="closeModal('modal-del')">CANCELAR</button>
    </div>
  </div>
</div>

<!-- DELETE EXPIRED MODAL -->
<div class="overlay" id="modal-del-exp">
  <div class="modal">
    <div class="modal-title">// LIMPIAR EXPIRADOS <button class="close-btn" onclick="closeModal('modal-del-exp')">✕</button></div>
    <p class="danger-msg">¿Eliminar <strong id="exp-count"></strong> usuarios expirados?<br><span style="color:#3a7ca5;font-size:11px">Esta acción no se puede deshacer.</span></p>
    <div class="modal-actions">
      <button class="btn btn-danger" onclick="deleteExpired()">🗑 ELIMINAR TODOS</button>
      <button class="btn btn-cancel" onclick="closeModal('modal-del-exp')">CANCELAR</button>
    </div>
  </div>
</div>

<!-- CHANGE PASSWORD MODAL -->
<div class="overlay" id="modal-chpass">
  <div class="modal">
    <div class="modal-title">// CAMBIAR CONTRASEÑA <button class="close-btn" onclick="closeModal('modal-chpass')">✕</button></div>
    <form method="POST" onsubmit="return validatePassForm()">
      <div class="field"><label>CONTRASEÑA ACTUAL</label><input type="password" name="current_pass" id="cp-current" placeholder="Contraseña actual"></div>
      <div class="field"><label>NUEVA CONTRASEÑA</label><input type="password" name="new_pass" id="cp-new" placeholder="Mínimo 6 caracteres"></div>
      <div class="field"><label>CONFIRMAR NUEVA CONTRASEÑA</label><input type="password" name="new_pass2" id="cp-new2" placeholder="Repetir nueva contraseña"></div>
      <?php if (!empty($pass_error ?? '')): ?>
        <div style="color:#ff4d6d;font-size:12px;margin-bottom:12px">⚠ <?= htmlspecialchars($pass_error) ?></div>
      <?php endif; ?>
      <?php if (!empty($pass_success ?? '')): ?>
        <div style="color:#00ff9d;font-size:12px;margin-bottom:12px">✓ <?= htmlspecialchars($pass_success) ?></div>
      <?php endif; ?>
      <div class="modal-actions">
        <button type="submit" name="change_panel_pass" class="btn btn-green">✓ ACTUALIZAR</button>
        <button type="button" class="btn btn-cancel" onclick="closeModal('modal-chpass')">CANCELAR</button>
      </div>
    </form>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let allUsers = [];
let currentFilter = 'all';
let globalToken = '';
let globalIP = '';

function validatePassForm() {
  const cur  = document.getElementById('cp-current').value;
  const n1   = document.getElementById('cp-new').value;
  const n2   = document.getElementById('cp-new2').value;
  if (!cur) { showToast('Ingresa la contraseña actual', 'err'); return false; }
  if (n1.length < 6) { showToast('Mínimo 6 caracteres', 'err'); return false; }
  if (n1 !== n2) { showToast('Las contraseñas no coinciden', 'err'); return false; }
  return true;
}

async function api(data) {
  const fd = new FormData();
  for (const k in data) fd.append(k, data[k]);
  const r = await fetch(window.location.href, { method: 'POST', body: fd });
  return r.json();
}

async function loadUsers() {
  document.getElementById('tbody').innerHTML = '<tr><td colspan="6" class="loading">⟳ Cargando...</td></tr>';
  const data = await api({ action: 'list' });
  allUsers = data;
  renderTable();
}

function renderTable() {
  const q = document.getElementById('search').value.toLowerCase();
  const list = allUsers.filter(u =>
    (currentFilter === 'all' || u.status === currentFilter) &&
    u.username.toLowerCase().includes(q)
  );
  document.getElementById('s-total').textContent = allUsers.length;
  document.getElementById('s-active').textContent = allUsers.filter(u => u.status === 'active').length;
  document.getElementById('s-expired').textContent = allUsers.filter(u => u.status === 'expired').length;
  if (!list.length) {
    document.getElementById('tbody').innerHTML = '<tr><td colspan="6" class="empty">Sin usuarios</td></tr>';
    return;
  }
  document.getElementById('tbody').innerHTML = list.map(u => {
    const badge = u.status === 'active'
      ? `<span class="badge badge-active"><span class="dot dot-active"></span>Activo</span>`
      : `<span class="badge badge-expired"><span class="dot dot-expired"></span>Expirado</span>`;
    const dl = u.days_left;
    const expCls = dl === '∞' ? 'expiry-ok' : dl < 0 ? 'expiry-bad' : dl <= 7 ? 'expiry-warn' : 'expiry-ok';
    const dlText = dl === '∞' ? 'Sin límite' : dl < 0 ? `Venció hace ${Math.abs(dl)}d` : `${dl}d restantes`;
    const connPct = Math.min(100, Math.round(u.conn_active / u.conn_limit * 100));
    const connCls = connPct >= 90 ? 'bar-red' : 'bar-blue';
    const onlineTag = u.conn_active > 0
      ? `<span class="online-tag">● ONLINE</span>`
      : `<span class="offline-tag">○ offline</span>`;
    return `<tr>
      <td><strong>${u.username}</strong>${onlineTag}</td>
      <td>${badge}</td>
      <td style="min-width:130px">
        <div class="conn-text">${u.conn_active}/${u.conn_limit}</div>
        <div class="bar-wrap"><div class="bar-inner ${connCls}" style="width:${connPct}%"></div></div>
      </td>
      <td><span class="${expCls}">${u.expiry}</span></td>
      <td><span class="${expCls}">${dlText}</span></td>
      <td>
        <button class="check-btn" onclick="checkOnline('${u.username}')">⚡</button>
        <button class="action-btn" onclick="openEdit('${u.username}',${u.conn_limit})">✎</button>
        <button class="del-btn" onclick="openDel('${u.username}')">✕</button>
      </td>
    </tr>`;
  }).join('');
}

function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}

async function createUser() {
  const username = document.getElementById('c-user').value.trim();
  const password = document.getElementById('c-pass').value;
  const days     = document.getElementById('c-days').value;
  const limit    = document.getElementById('c-limit').value;
  if (!username || !password) return showToast('Usuario y contraseña requeridos', 'err');
  const r = await api({ action: 'create', username, password, days, limit });
  if (r.ok) {
    closeModal('modal-create');
    loadUsers();
    showToast(r.msg);
    document.getElementById('c-user').value = '';
    document.getElementById('c-pass').value = '';
  } else showToast(r.msg, 'err');
}

// TOKEN FUNCTIONS
async function openTokenModal() {
  try {
    const r = await fetch('?token_info=1').then(x => x.json());
    globalToken = r.token;
    globalIP    = r.ip;
    document.getElementById('token-val').textContent = r.token;
    document.getElementById('token-form').style.display = 'block';
    document.getElementById('token-result').style.display = 'none';
    document.getElementById('t-user').value = '';
    openModal('modal-token');
  } catch(e) {
    showToast('Error al cargar token', 'err');
  }
}

async function createTokenUser() {
  const username = document.getElementById('t-user').value.trim();
  const days     = document.getElementById('t-days').value;
  const limit    = document.getElementById('t-limit').value;
  if (!username) return showToast('El TokenID es requerido', 'err');
  const r = await api({ action: 'create_token', username, days, limit });
  if (r.ok) {
    document.getElementById('r-ip').textContent     = r.ip || globalIP;
    document.getElementById('r-token').textContent  = r.token;
    document.getElementById('r-expiry').textContent = r.expiry;
    document.getElementById('r-limit').textContent  = r.limit;
    document.getElementById('token-form').style.display   = 'none';
    document.getElementById('token-result').style.display = 'block';
    loadUsers();
  } else showToast(r.msg, 'err');
}

function copyToken() {
  navigator.clipboard.writeText(globalToken).then(() => showToast('Token copiado'));
}

function copyResult() {
  const ip     = document.getElementById('r-ip').textContent;
  const token  = document.getElementById('r-token').textContent;
  const expiry = document.getElementById('r-expiry').textContent;
  const limit  = document.getElementById('r-limit').textContent;
  const text   = `IP: ${ip}\nToken: ${token}\nExpira em: ${expiry}\nLímite de conexión: ${limit}`;
  navigator.clipboard.writeText(text).then(() => showToast('Datos copiados'));
}

function resetTokenModal() {
  document.getElementById('token-form').style.display   = 'block';
  document.getElementById('token-result').style.display = 'none';
  document.getElementById('t-user').value = '';
}

function openEdit(user, limit) {
  document.getElementById('e-user').value = user;
  document.getElementById('e-title').textContent = user;
  document.getElementById('e-pass').value = '';
  document.getElementById('e-limit').value = limit;
  openModal('modal-edit');
}

async function saveEdit() {
  const user  = document.getElementById('e-user').value;
  const pass  = document.getElementById('e-pass').value;
  const days  = document.getElementById('e-days').value;
  const limit = document.getElementById('e-limit').value;
  if (pass) await api({ action: 'change_pass', username: user, password: pass });
  await api({ action: 'change_expiry', username: user, days });
  await api({ action: 'change_limit', username: user, limit });
  closeModal('modal-edit');
  loadUsers();
  showToast('Usuario actualizado');
}

function openDel(user) {
  document.getElementById('d-user').value = user;
  document.getElementById('d-name').textContent = user;
  openModal('modal-del');
}

async function deleteUser() {
  const user = document.getElementById('d-user').value;
  const r = await api({ action: 'delete', username: user });
  closeModal('modal-del');
  loadUsers();
  showToast(r.msg);
}

function confirmDeleteExpired() {
  const expired = allUsers.filter(u => u.status === 'expired');
  if (!expired.length) return showToast('No hay usuarios expirados', 'err');
  document.getElementById('exp-count').textContent = expired.length;
  openModal('modal-del-exp');
}

async function deleteExpired() {
  const r = await api({ action: 'delete_expired' });
  closeModal('modal-del-exp');
  loadUsers();
  showToast(r.msg);
}

async function checkOnline(user) {
  const r = await api({ action: 'check_online', username: user });
  if (r.online) showToast(`${user} ONLINE con ${r.connections} conexión(es)`);
  else showToast(`${user} está OFFLINE`, 'err');
}

function openModal(id)  { document.getElementById(id).classList.add('show'); }
function closeModal(id) { document.getElementById(id).classList.remove('show'); }

let toastTimer;
function showToast(msg, type = 'ok') {
  const t = document.getElementById('toast');
  t.textContent = (type === 'ok' ? '✓ ' : '○ ') + msg;
  t.className = `toast show toast-${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

async function loadOnline() {
  try {
    const r = await fetch('?online=1');
    const d = await r.json();
    document.getElementById('s-conn').textContent = d.online;
  } catch(e) {}
}

async function loadMonitor() {
  try {
    const r = await fetch('?monitor=1');
    const d = await r.json();
    const setBar = (id, val, warn=80) => {
      const el = document.getElementById(id);
      el.style.width = val + '%';
      el.className = 'mon-inner ' + (val >= warn ? 'mon-warn' : '');
    };
    document.getElementById('m-cpu').textContent  = d.cpu + '%';
    document.getElementById('m-ram').textContent  = d.mem_used + '%';
    document.getElementById('m-disk').textContent = d.disk + '%';
    document.getElementById('m-uptime').textContent = '↑ ' + d.uptime;
    setBar('m-cpu-bar', d.cpu);
    setBar('m-ram-bar', d.mem_used);
    setBar('m-disk-bar', d.disk, 90);
  } catch(e) {}
}

document.querySelectorAll('.overlay').forEach(o =>
  o.addEventListener('click', e => { if (e.target === o) o.classList.remove('show'); })
);

loadUsers();
loadOnline();
loadMonitor();
setInterval(loadOnline,  10000);
setInterval(loadMonitor, 5000);
</script>
<?php endif; ?>
</body>
</html>
