<?php
// ============================================================
// SSHPLUS MANAGER - Panel Web PHP - Version Final + Temas + Dropdown
// ============================================================
define('SESSION_NAME', 'sshplus_panel');
define('SECRET_FILE', '/etc/sshplus-panel/.secret');
session_name(SESSION_NAME);
session_start();

function loadPasswordHash() {
    if (!file_exists(SECRET_FILE)) {
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

    if ($action === 'list') { echo json_encode(getUsers()); exit; }

    if ($action === 'create') {
        $user  = preg_replace('/[^a-z0-9_]/', '', strtolower($_POST['username']));
        $pass  = $_POST['password'];
        $days  = intval($_POST['days']);
        $limit = intval($_POST['limit']);
        if (empty($user) || empty($pass) || $days < 1 || $limit < 1) {
            echo json_encode(['ok'=>false,'msg'=>'Datos incompletos']); exit;
        }
        shell_exec("sudo useradd -M -s /bin/false $user 2>&1");
        shell_exec("echo '$user:$pass' | sudo /usr/sbin/chpasswd 2>&1");
        shell_exec("sudo chage -E \$(date -d '+{$days} days' +%Y-%m-%d) $user 2>&1");
        file_put_contents("/etc/SSHPlus/senha/$user", $pass);
        saveLimitConn($user, $limit);
        echo json_encode(['ok'=>true,'msg'=>"Usuario $user creado correctamente"]); exit;
    }

    if ($action === 'create_token') {
        $user  = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $days  = intval($_POST['days']);
        $limit = intval($_POST['limit']);
        $pass  = trim(@file_get_contents('/etc/SSHPlus/Token.txt') ?: '');
        $ip    = trim(shell_exec("curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print \$1}'"));
        if (empty($user) || empty($pass) || $days < 1 || $limit < 1) {
            echo json_encode(['ok'=>false,'msg'=>'Datos incompletos o Token.txt no encontrado']); exit;
        }
        shell_exec("sudo useradd -M -s /bin/false $user 2>&1");
        shell_exec("echo '$user:$pass' | sudo /usr/sbin/chpasswd 2>&1");
        shell_exec("sudo chage -E \$(date -d '+{$days} days' +%Y-%m-%d) $user 2>&1");
        file_put_contents("/etc/SSHPlus/senha/$user", $pass);
        saveLimitConn($user, $limit);
        $expiry = date('d/m/Y', strtotime("+{$days} days"));
        echo json_encode(['ok'=>true,'msg'=>"Token $user creado",'token'=>$user,'ip'=>$ip,'expiry'=>$expiry,'limit'=>$limit]); exit;
    }

    if ($action === 'delete') {
        $user = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        shell_exec("sudo userdel -r $user 2>&1");
        @unlink("/etc/SSHPlus/senha/$user");
        deleteLimitConn($user);
        echo json_encode(['ok'=>true,'msg'=>"Usuario $user eliminado"]); exit;
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
        echo json_encode(['ok'=>true,'msg'=>"$count usuarios expirados eliminados"]); exit;
    }

    if ($action === 'check_online') {
        $user  = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $count = intval(trim(shell_exec("ps aux | grep 'sshd: $user' | grep -v grep | grep -v priv | wc -l") ?: '0'));
        echo json_encode(['ok'=>true,'online'=>$count > 0,'connections'=>$count]); exit;
    }

    if ($action === 'change_pass') {
        $user = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $pass = $_POST['password'];
        shell_exec("echo '$user:$pass' | sudo /usr/sbin/chpasswd 2>&1");
        file_put_contents("/etc/SSHPlus/senha/$user", $pass);
        echo json_encode(['ok'=>true,'msg'=>"Contraseña actualizada"]); exit;
    }

    if ($action === 'change_expiry') {
        $user = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $days = intval($_POST['days']);
        shell_exec("sudo chage -E \$(date -d '+{$days} days' +%Y-%m-%d) $user 2>&1");
        echo json_encode(['ok'=>true,'msg'=>"Expiración actualizada"]); exit;
    }

    if ($action === 'change_limit') {
        $user  = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['username']);
        $limit = intval($_POST['limit']);
        saveLimitConn($user, $limit);
        echo json_encode(['ok'=>true,'msg'=>"Límite actualizado"]); exit;
    }

    echo json_encode(['ok'=>false,'msg'=>'Acción desconocida']); exit;
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
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Caveat:wght@400;700&family=Lora:wght@400;600&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">

<script>
(function(){
    var t = localStorage.getItem('sshplus_theme') || 'dark';
    if (!['dark','light','paper','gaming'].includes(t)) t = 'dark';
    document.documentElement.setAttribute('data-theme', t);
})();
</script>

<style>
/* ============================================================
   🌙 DARK
   ============================================================ */
:root, [data-theme="dark"] {
    --bg-body: #060b14;
    --bg-card: #0d1321;
    --bg-card-alt: #0a1525;
    --bg-input: #0a0f1a;
    --bg-hover: rgba(0,200,255,0.04);
    --border: #1e3a5f;
    --border-soft: #0e2a45;
    --text: #e0f0ff;
    --text-muted: #3a7ca5;
    --text-soft: #7eb8ff;
    --accent: #00c8ff;
    --accent-2: #00ff9d;
    --accent-3: #ff4d6d;
    --accent-4: #ffbe0b;
    --glow: rgba(0,180,255,0.15);
    --glow-strong: rgba(0,200,255,0.4);
    --grid-color: rgba(0,200,255,0.03);
    --font-main: 'Share Tech Mono', monospace;
    --font-title: 'Orbitron', monospace;
    --radius: 14px;
    --radius-sm: 8px;
    --scanline-opacity: 1;
    --grid-opacity: 1;
    --card-glow: 0 0 60px rgba(0,180,255,0.15);
    --neon-text-shadow: 0 0 20px;
    --bar-glow: 0 0 8px;
    --border-login: #1e3a5f;
    --dropdown-shadow: 0 8px 30px rgba(0,0,0,0.5), 0 0 20px rgba(0,200,255,0.1);
}

/* ============================================================
   ☀️ LIGHT
   ============================================================ */
[data-theme="light"] {
    --bg-body: #f0f4f8;
    --bg-card: #ffffff;
    --bg-card-alt: #f7fafc;
    --bg-input: #ffffff;
    --bg-hover: rgba(0,100,200,0.06);
    --border: #d8e0e8;
    --border-soft: #e8edf2;
    --text: #1a2332;
    --text-muted: #6b7a8f;
    --text-soft: #3a5068;
    --accent: #0077cc;
    --accent-2: #00a86b;
    --accent-3: #d93652;
    --accent-4: #e89a00;
    --glow: rgba(0,100,200,0.08);
    --glow-strong: rgba(0,100,200,0.15);
    --grid-color: rgba(0,100,200,0.04);
    --font-main: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --font-title: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --radius: 12px;
    --radius-sm: 8px;
    --scanline-opacity: 0;
    --grid-opacity: 0.5;
    --card-glow: 0 2px 20px rgba(0,0,0,0.06);
    --neon-text-shadow: none;
    --bar-glow: none;
    --border-login: #d8e0e8;
    --dropdown-shadow: 0 8px 24px rgba(0,0,0,0.12);
}

/* ============================================================
   📜 PAPER
   ============================================================ */
[data-theme="paper"] {
    --bg-body: #f4f1ea;
    --bg-card: #fbfaf5;
    --bg-card-alt: #f7f3e8;
    --bg-input: #fdfcf7;
    --bg-hover: rgba(120,90,50,0.06);
    --border: #d4c9a8;
    --border-soft: #e6ddc2;
    --text: #3d3833;
    --text-muted: #8a7a5c;
    --text-soft: #6b5d45;
    --accent: #8b5a2b;
    --accent-2: #5a7a3a;
    --accent-3: #a84032;
    --accent-4: #c89030;
    --glow: rgba(120,90,50,0.1);
    --glow-strong: rgba(120,90,50,0.15);
    --grid-color: rgba(120,90,50,0.06);
    --font-main: 'Lora', Georgia, serif;
    --font-title: 'Caveat', cursive;
    --radius: 6px;
    --radius-sm: 4px;
    --scanline-opacity: 0;
    --grid-opacity: 0.4;
    --card-glow: 0 2px 12px rgba(120,90,50,0.08);
    --neon-text-shadow: none;
    --bar-glow: none;
    --border-login: #d4c9a8;
    --dropdown-shadow: 0 8px 20px rgba(120,90,50,0.15);
}

/* ============================================================
   🎮 GAMING
   ============================================================ */
[data-theme="gaming"] {
    --bg-body: #08000f;
    --bg-card: #110020;
    --bg-card-alt: #0d001a;
    --bg-input: #0a0015;
    --bg-hover: rgba(255,0,255,0.06);
    --border: #3a0066;
    --border-soft: #220040;
    --text: #f0e0ff;
    --text-muted: #8844bb;
    --text-soft: #cc77ff;
    --accent: #ff00ff;
    --accent-2: #39ff14;
    --accent-3: #ff003c;
    --accent-4: #00ffff;
    --glow: rgba(255,0,255,0.2);
    --glow-strong: rgba(255,0,255,0.5);
    --grid-color: rgba(255,0,255,0.04);
    --font-main: 'Rajdhani', 'Share Tech Mono', sans-serif;
    --font-title: 'Orbitron', monospace;
    --radius: 10px;
    --radius-sm: 6px;
    --scanline-opacity: 1;
    --grid-opacity: 1;
    --card-glow: 0 0 40px rgba(255,0,255,0.15), 0 0 80px rgba(0,255,255,0.05);
    --neon-text-shadow: 0 0 20px;
    --bar-glow: 0 0 12px;
    --border-login: #5500aa;
    --dropdown-shadow: 0 8px 30px rgba(255,0,255,0.3), 0 0 40px rgba(0,255,255,0.1);
}

/* ============================================================
   BASE
   ============================================================ */
*{box-sizing:border-box;margin:0;padding:0}

body{
    background:var(--bg-body);
    font-family:var(--font-main);
    color:var(--text);
    min-height:100vh;
    transition:background .4s, color .4s;
}

body::before{
    content:'';
    position:fixed;inset:0;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px);
    pointer-events:none;z-index:999;
    opacity:var(--scanline-opacity);
}

[data-theme="gaming"] body::before{
    background:repeating-linear-gradient(0deg,transparent,transparent 1px,rgba(255,0,255,0.015) 1px,rgba(255,0,255,0.015) 3px);
}

.grid-bg{
    position:fixed;inset:0;
    background-image:
        linear-gradient(var(--grid-color) 1px,transparent 1px),
        linear-gradient(90deg,var(--grid-color) 1px,transparent 1px);
    background-size:40px 40px;
    pointer-events:none;
    opacity:var(--grid-opacity);
    transition:opacity .4s;
}

[data-theme="paper"] .grid-bg{
    background-image:linear-gradient(var(--grid-color) 1px,transparent 1px);
    background-size:100% 32px;
}

[data-theme="gaming"] .grid-bg{background-size:50px 50px}

.wrap{max-width:1200px;margin:0 auto;padding:0 20px}

/* ============================================================
   SELECTOR DE TEMA
   ============================================================ */
.theme-switcher{
    display:flex;
    background:var(--bg-card);
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:4px;gap:2px;
    box-shadow:var(--card-glow);
    transition:all .4s;
}
.theme-btn{
    background:transparent;
    border:none;
    color:var(--text-muted);
    padding:7px 11px;
    cursor:pointer;
    border-radius:calc(var(--radius) - 4px);
    font-size:14px;
    transition:all .25s;
    display:flex;align-items:center;gap:4px;
    font-family:var(--font-main);
    line-height:1;
}
.theme-btn:hover{color:var(--text);background:var(--bg-hover)}
.theme-btn.active{
    background:var(--accent);
    color:var(--bg-body);
    box-shadow:0 0 12px var(--glow);
}
.theme-btn span.label{font-size:10px;letter-spacing:1px;display:none}
@media(min-width:900px){.theme-btn span.label{display:inline}}

/* ============================================================
   LOGIN
   ============================================================ */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{
    background:var(--bg-card);
    border:1px solid var(--border-login);
    border-radius:var(--radius);
    padding:48px 40px;width:380px;text-align:center;
    box-shadow:var(--card-glow);
    transition:all .4s;
    position:relative;
    overflow:hidden;
}

[data-theme="gaming"] .login-box{border:2px solid transparent;background-clip:padding-box}
[data-theme="gaming"] .login-box::after{
    content:'';
    position:absolute;inset:-2px;
    border-radius:inherit;
    background:linear-gradient(45deg,#ff00ff,#00ffff,#39ff14,#ff00ff,#00ffff);
    background-size:400% 400%;
    z-index:-1;
    animation:rgbBorder 4s linear infinite;
}

.login-title{
    font-family:var(--font-title);
    font-size:24px;font-weight:900;letter-spacing:3px;
    background:linear-gradient(90deg,var(--accent),var(--text-soft));
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
    margin-bottom:4px;
}
[data-theme="paper"] .login-title{font-size:36px;letter-spacing:1px}
[data-theme="gaming"] .login-title{
    font-size:28px;
    background:linear-gradient(90deg,#ff00ff,#00ffff,#39ff14);
    background-size:200% auto;
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
    animation:rgbText 3s linear infinite;
    filter:drop-shadow(0 0 10px rgba(255,0,255,0.5));
}
.login-title span{-webkit-text-fill-color:var(--accent-2)}
[data-theme="gaming"] .login-title span{-webkit-text-fill-color:#39ff14}

.login-sub{color:var(--text-muted);font-size:11px;letter-spacing:2px;margin-bottom:32px}
[data-theme="paper"] .login-sub{font-style:italic;font-size:14px;letter-spacing:0}
[data-theme="gaming"] .login-sub{color:#8844bb;font-size:12px;letter-spacing:4px}

.login-input{
    width:100%;
    background:var(--bg-input);
    border:1px solid var(--border);
    border-radius:var(--radius-sm);
    padding:12px 16px;
    color:var(--text);
    font-family:var(--font-main);
    font-size:14px;outline:none;
    margin-bottom:16px;
    transition:border-color .2s, background .4s;
}
.login-input:focus{border-color:var(--accent);box-shadow:0 0 10px var(--glow)}

.login-btn{
    width:100%;
    background:transparent;
    border:1px solid var(--accent-2);
    color:var(--accent-2);
    border-radius:var(--radius-sm);
    padding:12px;cursor:pointer;
    font-family:var(--font-main);
    font-size:13px;letter-spacing:1px;
    transition:all .2s;
}
.login-btn:hover{background:var(--accent-2);color:var(--bg-body)}
[data-theme="gaming"] .login-btn{border-color:#39ff14;color:#39ff14;text-shadow:0 0 8px rgba(57,255,20,0.5)}
[data-theme="gaming"] .login-btn:hover{background:#39ff14;color:#08000f;box-shadow:0 0 20px rgba(57,255,20,0.5)}

.login-err{color:var(--accent-3);font-size:12px;margin-top:8px}
.login-theme-wrap{margin-top:24px;display:flex;justify-content:center}

/* ============================================================
   HEADER
   ============================================================ */
.header{
    padding:28px 0 20px;
    display:flex;justify-content:space-between;align-items:center;
    border-bottom:1px solid var(--border-soft);
    flex-wrap:wrap;gap:12px;
}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{
    width:36px;height:36px;
    background:linear-gradient(135deg,var(--accent),var(--text-soft));
    border-radius:var(--radius-sm);
    display:flex;align-items:center;justify-content:center;
    font-size:18px;
    box-shadow:0 0 20px var(--glow-strong);
    transition:all .4s;
}
[data-theme="paper"] .logo-icon{background:var(--bg-card-alt);border:2px solid var(--accent);box-shadow:none}
[data-theme="gaming"] .logo-icon{
    background:linear-gradient(135deg,#ff00ff,#00ffff);
    box-shadow:0 0 20px rgba(255,0,255,0.6);
    animation:rgbPulse 2s ease-in-out infinite;
}

.logo-text{
    font-family:var(--font-title);
    font-size:20px;font-weight:900;letter-spacing:3px;
    background:linear-gradient(90deg,var(--accent),var(--text-soft));
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
[data-theme="paper"] .logo-text{font-size:28px;letter-spacing:1px;font-weight:700}
[data-theme="gaming"] .logo-text{
    font-size:22px;
    background:linear-gradient(90deg,#ff00ff,#00ffff,#39ff14);
    background-size:200% auto;
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
    animation:rgbText 3s linear infinite;
    filter:drop-shadow(0 0 8px rgba(255,0,255,0.4));
}
.logo-text span{-webkit-text-fill-color:var(--accent-2)}
[data-theme="gaming"] .logo-text span{-webkit-text-fill-color:#39ff14}

.logo-sub{color:var(--text-muted);font-size:10px;margin-top:3px;letter-spacing:2px}
[data-theme="paper"] .logo-sub{font-style:italic;font-size:12px;letter-spacing:0}
[data-theme="gaming"] .logo-sub{letter-spacing:4px;color:#8844bb}

.header-right{display:flex;gap:10px;align-items:center;flex-wrap:wrap}

/* ============================================================
   🆕 DROPDOWN "CREAR USUARIO"
   ============================================================ */
.dropdown-wrap{position:relative}

.btn-create{
    background:transparent;
    border:1px solid var(--accent-2);
    color:var(--accent-2);
    border-radius:var(--radius-sm);
    padding:10px 16px;
    cursor:pointer;
    font-family:var(--font-main);
    font-size:12px;
    letter-spacing:1px;
    transition:all .2s;
    display:flex;align-items:center;gap:8px;
    font-weight:600;
}
.btn-create:hover{
    background:var(--accent-2);
    color:var(--bg-body);
}
.btn-create .arrow{
    font-size:9px;
    transition:transform .25s ease;
    margin-left:2px;
}
.dropdown-wrap.open .btn-create .arrow{
    transform:rotate(180deg);
}
.dropdown-wrap.open .btn-create{
    background:var(--accent-2);
    color:var(--bg-body);
}

/* Gaming glow */
[data-theme="gaming"] .btn-create{
    border-color:#39ff14;color:#39ff14;
    text-shadow:0 0 6px rgba(57,255,20,0.4);
}
[data-theme="gaming"] .btn-create:hover,
[data-theme="gaming"] .dropdown-wrap.open .btn-create{
    background:#39ff14;color:#08000f;
    box-shadow:0 0 20px rgba(57,255,20,0.5);
}

/* Menú desplegable */
.dropdown-menu{
    position:absolute;
    top:calc(100% + 8px);
    right:0;
    min-width:240px;
    background:var(--bg-card);
    border:1px solid var(--border);
    border-radius:var(--radius);
    box-shadow:var(--dropdown-shadow);
    padding:6px;
    z-index:100;
    opacity:0;
    visibility:hidden;
    transform:translateY(-8px);
    transition:opacity .2s ease, transform .2s ease, visibility .2s;
}
.dropdown-wrap.open .dropdown-menu{
    opacity:1;
    visibility:visible;
    transform:translateY(0);
}

/* Triángulo indicador (flecha arriba) */
.dropdown-menu::before{
    content:'';
    position:absolute;
    top:-6px;
    right:18px;
    width:12px;height:12px;
    background:var(--bg-card);
    border-left:1px solid var(--border);
    border-top:1px solid var(--border);
    transform:rotate(45deg);
}

.dropdown-item{
    display:flex;
    align-items:center;
    gap:12px;
    padding:12px 14px;
    background:transparent;
    border:none;
    width:100%;
    text-align:left;
    cursor:pointer;
    border-radius:calc(var(--radius) - 4px);
    color:var(--text);
    font-family:var(--font-main);
    font-size:13px;
    transition:all .15s;
}
.dropdown-item:hover{
    background:var(--bg-hover);
}
.dropdown-item .icon{
    width:36px;height:36px;
    border-radius:calc(var(--radius) - 4px);
    display:flex;align-items:center;justify-content:center;
    font-size:18px;
    flex-shrink:0;
    transition:all .2s;
}
.dropdown-item .text-wrap{
    display:flex;flex-direction:column;gap:2px;flex:1;
}
.dropdown-item .title{
    font-weight:600;
    letter-spacing:.5px;
}
.dropdown-item .desc{
    font-size:10px;
    color:var(--text-muted);
    letter-spacing:.3px;
}

/* Item Usuario Normal (verde) */
.dropdown-item.item-user .icon{
    background:color-mix(in srgb,var(--accent-2) 15%,transparent);
    border:1px solid color-mix(in srgb,var(--accent-2) 30%,transparent);
    color:var(--accent-2);
}
.dropdown-item.item-user .title{color:var(--accent-2)}
.dropdown-item.item-user:hover .icon{
    background:var(--accent-2);
    color:var(--bg-body);
}

/* Item Token (amarillo) */
.dropdown-item.item-token .icon{
    background:color-mix(in srgb,var(--accent-4) 15%,transparent);
    border:1px solid color-mix(in srgb,var(--accent-4) 30%,transparent);
    color:var(--accent-4);
}
.dropdown-item.item-token .title{color:var(--accent-4)}
.dropdown-item.item-token:hover .icon{
    background:var(--accent-4);
    color:var(--bg-body);
}

/* Gaming: glow en items */
[data-theme="gaming"] .dropdown-item.item-user:hover .icon{
    box-shadow:0 0 15px rgba(57,255,20,0.5);
}
[data-theme="gaming"] .dropdown-item.item-token:hover .icon{
    box-shadow:0 0 15px rgba(0,255,255,0.5);
}
[data-theme="gaming"] .dropdown-item.item-token .icon{
    background:rgba(0,255,255,0.1);
    border-color:rgba(0,255,255,0.3);
    color:#00ffff;
}
[data-theme="gaming"] .dropdown-item.item-token .title{color:#00ffff}
[data-theme="gaming"] .dropdown-item.item-token:hover .icon{background:#00ffff;color:#08000f}

/* Separador */
.dropdown-sep{
    height:1px;
    background:var(--border-soft);
    margin:4px 8px;
}

/* ============================================================
   STATS
   ============================================================ */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}
.stat-card{
    background:linear-gradient(135deg,var(--bg-card),var(--bg-card-alt));
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:18px 20px;
    position:relative;overflow:hidden;
    transition:all .4s;
    box-shadow:var(--card-glow);
}
.stat-card::before{
    content:'';position:absolute;top:0;left:0;width:100%;height:2px;
}
.stat-card:nth-child(1)::before{background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.stat-card:nth-child(2)::before{background:linear-gradient(90deg,transparent,var(--accent-2),transparent)}
.stat-card:nth-child(3)::before{background:linear-gradient(90deg,transparent,var(--accent-3),transparent)}
.stat-card:nth-child(4)::before{background:linear-gradient(90deg,transparent,var(--accent-4),transparent)}

[data-theme="gaming"] .stat-card{border-color:#3a0066}
[data-theme="gaming"] .stat-card:nth-child(1){border-top:2px solid #ff00ff}
[data-theme="gaming"] .stat-card:nth-child(2){border-top:2px solid #39ff14}
[data-theme="gaming"] .stat-card:nth-child(3){border-top:2px solid #ff003c}
[data-theme="gaming"] .stat-card:nth-child(4){border-top:2px solid #00ffff}

.stat-label{color:var(--text-muted);font-size:10px;letter-spacing:2px;margin-bottom:6px}
[data-theme="paper"] .stat-label{font-size:12px;letter-spacing:0;font-style:italic}
[data-theme="gaming"] .stat-label{letter-spacing:3px;font-size:11px;font-weight:600}

.stat-value{font-family:var(--font-title);font-weight:700;font-size:30px}
.stat-card:nth-child(1) .stat-value{color:var(--accent);text-shadow:var(--neon-text-shadow) var(--accent)}
.stat-card:nth-child(2) .stat-value{color:var(--accent-2);text-shadow:var(--neon-text-shadow) var(--accent-2)}
.stat-card:nth-child(3) .stat-value{color:var(--accent-3);text-shadow:var(--neon-text-shadow) var(--accent-3)}
.stat-card:nth-child(4) .stat-value{color:var(--accent-4);text-shadow:var(--neon-text-shadow) var(--accent-4)}

[data-theme="light"] .stat-value{text-shadow:none}
[data-theme="paper"] .stat-value{font-size:32px;text-shadow:none}
[data-theme="gaming"] .stat-value{font-size:32px}

/* ============================================================
   MONITOR
   ============================================================ */
.monitor{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px}
.mon-card{
    background:var(--bg-card);
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:16px 20px;
    transition:all .4s;
    box-shadow:var(--card-glow);
}
.mon-label{
    color:var(--text-muted);font-size:10px;letter-spacing:2px;
    margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;
}
[data-theme="paper"] .mon-label{font-size:12px;letter-spacing:0;font-style:italic}
[data-theme="gaming"] .mon-label{letter-spacing:3px;font-weight:600}

.mon-pct{font-family:var(--font-title);font-size:20px;font-weight:700;color:var(--text)}
.mon-bar{background:var(--bg-input);border-radius:4px;height:8px;margin-top:8px;overflow:hidden}
.mon-inner{height:100%;border-radius:4px;transition:width 1s ease, background .4s}
.mon-cpu .mon-inner{background:var(--accent);box-shadow:var(--bar-glow) var(--accent)}
.mon-ram .mon-inner{background:var(--accent-2);box-shadow:var(--bar-glow) var(--accent-2)}
.mon-disk .mon-inner{background:var(--accent-4);box-shadow:var(--bar-glow) var(--accent-4)}

.mon-warn{background:var(--accent-3)!important;box-shadow:var(--bar-glow) var(--accent-3)!important}
.uptime-val{color:var(--text-soft);font-size:12px;margin-top:6px}

/* ============================================================
   TOOLBAR
   ============================================================ */
.toolbar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.search-input{
    background:var(--bg-card);border:1px solid var(--border);
    border-radius:10px;padding:10px 14px;color:var(--text);
    font-family:var(--font-main);font-size:13px;outline:none;
    flex:1;min-width:180px;transition:border-color .2s, background .4s;
}
.search-input:focus{border-color:var(--accent)}
.filter-btn{
    background:transparent;border:1px solid var(--border);
    color:var(--text-muted);border-radius:10px;padding:10px 14px;
    cursor:pointer;font-family:var(--font-main);font-size:11px;
    letter-spacing:1px;transition:all .2s;
}
.filter-btn.active{
    background:color-mix(in srgb,var(--accent) 15%,transparent);
    border-color:var(--accent);color:var(--accent);
}
.btn-del-exp{
    background:transparent;
    border:1px solid color-mix(in srgb,var(--accent-3) 35%,transparent);
    color:var(--accent-3);border-radius:10px;padding:10px 14px;
    cursor:pointer;font-family:var(--font-main);font-size:11px;
    letter-spacing:1px;transition:all .2s;
}
.btn-del-exp:hover{background:color-mix(in srgb,var(--accent-3) 15%,transparent)}

/* ============================================================
   TABLA
   ============================================================ */
.table-wrap{
    background:var(--bg-card);border:1px solid var(--border);
    border-radius:var(--radius);overflow:hidden;margin-bottom:40px;
    transition:all .4s;box-shadow:var(--card-glow);
}
.tbl{width:100%;border-collapse:collapse}
.tbl th{
    padding:13px 16px;text-align:left;color:var(--text-muted);
    font-size:10px;letter-spacing:2px;font-weight:400;
    border-bottom:1px solid var(--border);
}
[data-theme="paper"] .tbl th{font-size:12px;letter-spacing:0;font-style:italic;text-transform:none}
[data-theme="gaming"] .tbl th{letter-spacing:3px;font-weight:600;font-size:11px}

.tbl td{
    padding:13px 16px;border-bottom:1px solid var(--border-soft);
    transition:background .15s;vertical-align:middle;
}
.tbl tr:hover td{background:var(--bg-hover)}
.tbl tr:last-child td{border-bottom:none}

.badge{display:inline-flex;align-items:center;gap:5px;border-radius:20px;padding:3px 10px;font-size:10px;letter-spacing:1px}
.badge-active{
    background:color-mix(in srgb,var(--accent-2) 12%,transparent);
    border:1px solid color-mix(in srgb,var(--accent-2) 35%,transparent);
    color:var(--accent-2);
}
.badge-expired{
    background:color-mix(in srgb,var(--accent-3) 12%,transparent);
    border:1px solid color-mix(in srgb,var(--accent-3) 35%,transparent);
    color:var(--accent-3);
}
.dot{width:5px;height:5px;border-radius:50%;display:inline-block}
.dot-active{background:var(--accent-2);box-shadow:0 0 5px var(--accent-2);animation:pulse 2s infinite}
.dot-expired{background:var(--accent-3)}

.expiry-ok{color:var(--accent-2);font-size:12px}
.expiry-warn{color:var(--accent-4);font-size:12px}
.expiry-bad{color:var(--accent-3);font-size:12px}

.conn-text{font-size:12px;margin-bottom:4px}
.bar-wrap{background:var(--bg-input);border-radius:3px;height:5px;overflow:hidden}
.bar-inner{height:100%;border-radius:3px;transition:width .5s}
.bar-blue{background:var(--accent);box-shadow:var(--bar-glow) var(--accent)}
.bar-red{background:var(--accent-3);box-shadow:var(--bar-glow) var(--accent-3)}

.action-btn{
    background:none;border:1px solid var(--border);color:var(--text-soft);
    border-radius:6px;padding:5px 10px;cursor:pointer;font-size:11px;
    font-family:var(--font-main);transition:all .2s;margin-right:4px;
}
.action-btn:hover{border-color:var(--accent);color:var(--accent)}
.check-btn{
    background:none;
    border:1px solid color-mix(in srgb,var(--accent-4) 30%,transparent);
    color:var(--accent-4);border-radius:6px;padding:5px 10px;
    cursor:pointer;font-size:11px;font-family:var(--font-main);
    transition:all .2s;margin-right:4px;
}
.check-btn:hover{background:color-mix(in srgb,var(--accent-4) 12%,transparent)}
.del-btn{
    background:none;
    border:1px solid color-mix(in srgb,var(--accent-3) 35%,transparent);
    color:var(--accent-3);border-radius:6px;padding:5px 10px;
    cursor:pointer;font-size:11px;font-family:var(--font-main);transition:all .2s;
}
.del-btn:hover{background:color-mix(in srgb,var(--accent-3) 15%,transparent)}

.online-tag{
    display:inline-block;
    background:color-mix(in srgb,var(--accent-2) 15%,transparent);
    border:1px solid color-mix(in srgb,var(--accent-2) 30%,transparent);
    color:var(--accent-2);border-radius:4px;padding:2px 8px;
    font-size:10px;margin-left:6px;animation:pulse 2s infinite;
}
.offline-tag{
    display:inline-block;
    background:color-mix(in srgb,var(--text-muted) 10%,transparent);
    border:1px solid color-mix(in srgb,var(--text-muted) 20%,transparent);
    color:var(--text-muted);border-radius:4px;padding:2px 8px;
    font-size:10px;margin-left:6px;
}
.empty{padding:40px;text-align:center;color:var(--text-muted)}

/* ============================================================
   MODALES
   ============================================================ */
.overlay{
    display:none;position:fixed;inset:0;
    background:rgba(0,0,0,0.8);backdrop-filter:blur(6px);
    z-index:1000;align-items:center;justify-content:center;
}
[data-theme="light"] .overlay{background:rgba(20,30,50,0.5)}
[data-theme="paper"] .overlay{background:rgba(60,50,30,0.5)}
[data-theme="gaming"] .overlay{background:rgba(10,0,20,0.9);backdrop-filter:blur(10px)}

.overlay.show{display:flex}
.modal{
    background:var(--bg-card);border:1px solid var(--border);
    border-radius:var(--radius);padding:28px;
    width:90%;max-width:460px;
    box-shadow:var(--card-glow);
    animation:fadeIn .2s ease;
    transition:background .4s, border-color .4s;
}
[data-theme="gaming"] .modal{
    border:1px solid #5500aa;
    box-shadow:0 0 40px rgba(255,0,255,0.2), 0 0 80px rgba(0,255,255,0.05);
}

.modal-title{
    color:var(--accent);font-family:var(--font-title);
    font-size:14px;margin-bottom:20px;
    display:flex;justify-content:space-between;align-items:center;
    letter-spacing:2px;
}
[data-theme="paper"] .modal-title{font-size:22px;letter-spacing:0}
[data-theme="gaming"] .modal-title{font-size:15px;letter-spacing:3px;text-shadow:0 0 10px var(--accent)}

.close-btn{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:18px}
.close-btn:hover{color:var(--text)}

.field{margin-bottom:14px}
.field label{display:block;color:var(--text-soft);font-size:10px;letter-spacing:1px;margin-bottom:5px}
[data-theme="paper"] .field label{font-size:12px;letter-spacing:0;font-style:italic}
[data-theme="gaming"] .field label{letter-spacing:2px;font-weight:600}

.field input,.field select{
    width:100%;background:var(--bg-input);border:1px solid var(--border);
    border-radius:7px;padding:9px 12px;color:var(--text);
    font-family:var(--font-main);font-size:13px;outline:none;
    transition:border-color .2s, background .4s;
}
.field input:focus,.field select:focus{border-color:var(--accent)}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}

.btn{
    border-radius:7px;padding:9px 18px;cursor:pointer;
    font-family:var(--font-main);font-size:12px;letter-spacing:1px;
    transition:all .2s;border:1px solid;width:100%;
}
.btn-green{background:transparent;border-color:var(--accent-2);color:var(--accent-2)}
.btn-green:hover{background:var(--accent-2);color:var(--bg-body)}
.btn-yellow{background:transparent;border-color:var(--accent-4);color:var(--accent-4)}
.btn-yellow:hover{background:var(--accent-4);color:var(--bg-body)}
.btn-cancel{background:transparent;border-color:var(--border);color:var(--text-muted)}
.btn-cancel:hover{border-color:var(--text-muted);color:var(--text)}
.btn-danger{background:var(--accent-3);border-color:var(--accent-3);color:#fff}
.btn-danger:hover{opacity:.85}

.btn-refresh{
    background:transparent;border:1px solid var(--border);color:var(--text-muted);
    border-radius:var(--radius-sm);padding:10px 16px;cursor:pointer;
    font-family:var(--font-main);font-size:12px;transition:all .2s;
}
.btn-refresh:hover{border-color:var(--accent);color:var(--accent)}
.btn-logout{
    background:transparent;
    border:1px solid color-mix(in srgb,var(--accent-3) 25%,transparent);
    color:var(--accent-3);border-radius:var(--radius-sm);
    padding:10px 16px;cursor:pointer;font-family:var(--font-main);
    font-size:12px;transition:all .2s;text-decoration:none;
}
.btn-logout:hover{background:color-mix(in srgb,var(--accent-3) 12%,transparent)}

.modal-actions{display:flex;gap:10px;margin-top:8px}
.danger-msg{color:var(--accent-3);text-align:center;margin:8px 0 20px;font-size:13px;line-height:1.8}
.danger-msg strong{color:var(--text)}
.result-box{
    background:var(--bg-input);border:1px solid var(--border);
    border-radius:10px;padding:16px;font-family:var(--font-main);
    font-size:13px;line-height:2.2;margin-bottom:16px;
}

/* Toast */
.toast{
    position:fixed;bottom:28px;right:28px;
    border-radius:10px;padding:12px 20px;
    font-size:12px;font-family:var(--font-main);
    z-index:2000;display:none;animation:fadeIn .3s ease;
}
.toast.show{display:block}
.toast-ok{
    background:var(--bg-card);border:1px solid var(--accent-2);
    color:var(--accent-2);box-shadow:0 0 20px color-mix(in srgb,var(--accent-2) 25%,transparent);
}
.toast-err{
    background:var(--bg-card);border:1px solid var(--accent-3);
    color:var(--accent-3);box-shadow:0 0 20px color-mix(in srgb,var(--accent-3) 25%,transparent);
}
[data-theme="light"] .toast-ok,
[data-theme="light"] .toast-err,
[data-theme="paper"] .toast-ok,
[data-theme="paper"] .toast-err{box-shadow:0 4px 20px rgba(0,0,0,0.15)}

.loading{text-align:center;padding:40px;color:var(--text-muted);font-size:13px}

@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes rgbBorder{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
@keyframes rgbText{0%{background-position:0% center}100%{background-position:200% center}}
@keyframes rgbPulse{0%,100%{box-shadow:0 0 15px rgba(255,0,255,0.6)}33%{box-shadow:0 0 15px rgba(0,255,255,0.6)}66%{box-shadow:0 0 15px rgba(57,255,20,0.6)}}

::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:var(--bg-body)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
[data-theme="gaming"] ::-webkit-scrollbar-thumb{background:#5500aa}

@media(max-width:700px){
    .stats{grid-template-columns:1fr 1fr}
    .monitor{grid-template-columns:1fr}
    .header{flex-direction:column;align-items:flex-start}
    .theme-switcher{align-self:flex-start}
    .login-box{width:95%;padding:32px 24px}
    .dropdown-menu{right:0;left:auto;min-width:220px}
}
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
                <div style="color:var(--accent-2);font-size:12px;margin-top:8px">✓ <?= htmlspecialchars($pass_success) ?></div>
            <?php endif; ?>
            <?php if (!empty($login_error)): ?>
                <div class="login-err">⚠ <?= htmlspecialchars($login_error) ?></div>
            <?php endif; ?>
        </form>
        <div class="login-theme-wrap">
            <div class="theme-switcher">
                <button class="theme-btn" data-theme-set="dark" title="Oscuro">🌙<span class="label">Oscuro</span></button>
                <button class="theme-btn" data-theme-set="light" title="Claro">☀️<span class="label">Claro</span></button>
                <button class="theme-btn" data-theme-set="paper" title="Papel">📜<span class="label">Papel</span></button>
                <button class="theme-btn" data-theme-set="gaming" title="Gaming">🎮<span class="label">Gaming</span></button>
            </div>
        </div>
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
            <div class="theme-switcher">
                <button class="theme-btn" data-theme-set="dark" title="Oscuro">🌙<span class="label">Oscuro</span></button>
                <button class="theme-btn" data-theme-set="light" title="Claro">☀️<span class="label">Claro</span></button>
                <button class="theme-btn" data-theme-set="paper" title="Papel">📜<span class="label">Papel</span></button>
                <button class="theme-btn" data-theme-set="gaming" title="Gaming">🎮<span class="label">Gaming</span></button>
            </div>
            <button class="btn-refresh" onclick="loadUsers()">↻ Actualizar</button>

            <!-- 🆕 DROPDOWN "CREAR USUARIO" -->
            <div class="dropdown-wrap" id="dropdown-create">
                <button class="btn-create" onclick="toggleDropdown(event)">
                    <span>+</span>
                    <span>CREAR USUARIO</span>
                    <span class="arrow">▼</span>
                </button>
                <div class="dropdown-menu">
                    <button class="dropdown-item item-user" onclick="openCreateUser()">
                        <div class="icon">👤</div>
                        <div class="text-wrap">
                            <div class="title">Usuario Normal</div>
                            <div class="desc">Con contraseña personalizada</div>
                        </div>
                    </button>
                    <div class="dropdown-sep"></div>
                    <button class="dropdown-item item-token" onclick="openCreateToken()">
                        <div class="icon">⚡</div>
                        <div class="text-wrap">
                            <div class="title">Con Token</div>
                            <div class="desc">Usando Token.txt automático</div>
                        </div>
                    </button>
                </div>
            </div>

            <button class="btn-refresh" onclick="openModal('modal-chpass')" style="border-color:var(--text-soft);color:var(--text-soft)">🔑 Contraseña</button>
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
        <div class="modal-title">// CREAR USUARIO NORMAL <button class="close-btn" onclick="closeModal('modal-create')">✕</button></div>
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
        <div class="modal-title" style="color:var(--accent-4)">// CREAR CON TOKEN <button class="close-btn" onclick="closeModal('modal-token')">✕</button></div>
        <div id="token-form">
            <div style="background:var(--bg-card-alt);border:1px solid color-mix(in srgb,var(--accent-4) 25%,transparent);border-radius:8px;padding:12px 16px;margin-bottom:16px">
                <div style="color:var(--text-muted);font-size:10px;letter-spacing:1px;margin-bottom:4px">TOKEN GENERAL (contraseña automática)</div>
                <div style="display:flex;align-items:center;gap:10px">
                    <span id="token-val" style="color:var(--accent-4);font-family:monospace;font-size:14px;letter-spacing:2px;flex:1">—</span>
                    <button onclick="copyToken()" style="background:none;border:1px solid color-mix(in srgb,var(--accent-4) 30%,transparent);color:var(--accent-4);border-radius:6px;padding:4px 10px;cursor:pointer;font-size:11px;font-family:monospace">⎘</button>
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
        <div id="token-result" style="display:none">
            <div style="text-align:center;color:var(--accent-2);font-size:16px;margin-bottom:16px">✓ CUENTA SSH CREADA</div>
            <div class="result-box">
                <div><span style="color:var(--text-muted)">IP: </span><span style="color:var(--accent)" id="r-ip">—</span></div>
                <div><span style="color:var(--text-muted)">Token: </span><span style="color:var(--accent-4)" id="r-token">—</span></div>
                <div><span style="color:var(--text-muted)">Expira em: </span><span style="color:var(--accent-2)" id="r-expiry">—</span></div>
                <div><span style="color:var(--text-muted)">Límite de conexión: </span><span style="color:var(--accent-2)" id="r-limit">—</span></div>
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
        <p class="danger-msg">¿Eliminar al usuario <strong id="d-name"></strong>?<br><span style="color:var(--text-muted);font-size:11px">Esta acción no se puede deshacer.</span></p>
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
        <p class="danger-msg">¿Eliminar <strong id="exp-count"></strong> usuarios expirados?<br><span style="color:var(--text-muted);font-size:11px">Esta acción no se puede deshacer.</span></p>
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
                <div style="color:var(--accent-3);font-size:12px;margin-bottom:12px">⚠ <?= htmlspecialchars($pass_error) ?></div>
            <?php endif; ?>
            <?php if (!empty($pass_success ?? '')): ?>
                <div style="color:var(--accent-2);font-size:12px;margin-bottom:12px">✓ <?= htmlspecialchars($pass_success) ?></div>
            <?php endif; ?>
            <div class="modal-actions">
                <button type="submit" name="change_panel_pass" class="btn btn-green">✓ ACTUALIZAR</button>
                <button type="button" class="btn btn-cancel" onclick="closeModal('modal-chpass')">CANCELAR</button>
            </div>
        </form>
    </div>
</div>

<div class="toast" id="toast"></div>
<?php endif; ?>

<!-- ═══ FOOTER SSHPLUS MANAGER ═══ -->
<style>
.sshplus-footer {
  margin-top: 50px;
  padding: 30px 20px;
  background: var(--bg-card);
  border-top: 1px solid var(--border);
  text-align: center;
  font-family: var(--font-main);
  color: var(--text-muted);
  transition: all 0.4s ease;
  box-shadow: var(--card-glow);
}

.sshplus-footer .footer-brand {
  font-family: var(--font-title);
  font-size: 18px;
  font-weight: 900;
  letter-spacing: 3px;
  background: linear-gradient(90deg, var(--accent), var(--text-soft));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 12px;
  transition: all 0.4s;
}

[data-theme="paper"] .sshplus-footer .footer-brand {
  font-size: 24px;
  letter-spacing: 1px;
}

[data-theme="gaming"] .sshplus-footer .footer-brand {
  font-size: 20px;
  background: linear-gradient(90deg, #ff00ff, #00ffff, #39ff14);
  background-size: 200% auto;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  animation: rgbText 3s linear infinite;
  filter: drop-shadow(0 0 10px rgba(255,0,255,0.5));
}

.sshplus-footer .footer-copy {
  font-size: 13px;
  margin-bottom: 10px;
  color: var(--text-soft);
}

[data-theme="paper"] .sshplus-footer .footer-copy {
  font-style: italic;
  font-size: 14px;
}

.sshplus-footer .footer-links {
  margin: 15px 0;
  display: flex;
  justify-content: center;
  gap: 15px;
  flex-wrap: wrap;
}

.sshplus-footer .footer-link {
  color: var(--accent);
  text-decoration: none;
  font-size: 12px;
  padding: 6px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  transition: all 0.3s;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.sshplus-footer .footer-link:hover {
  background: var(--bg-hover);
  border-color: var(--accent);
  box-shadow: 0 0 10px var(--glow);
}

[data-theme="gaming"] .sshplus-footer .footer-link {
  border-color: #5500aa;
  box-shadow: 0 0 8px rgba(255,0,255,0.2);
}

[data-theme="gaming"] .sshplus-footer .footer-link:hover {
  border-color: #ff00ff;
  box-shadow: 0 0 15px rgba(255,0,255,0.5);
}

.sshplus-footer .footer-version {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 12px;
  opacity: 0.7;
}

[data-theme="paper"] .sshplus-footer .footer-version {
  font-style: italic;
}

.sshplus-footer .footer-separator {
  width: 60px;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  margin: 15px auto;
  opacity: 0.5;
}
</style>

<footer class="sshplus-footer">
  <div class="footer-brand">⚡ SSHPLUS MANAGER</div>
  <div class="footer-copy">
    © <?php echo date('Y'); ?> <strong style="color: var(--accent);">CloudGT</strong> - Todos los derechos reservados
  </div>
  
  <div class="footer-version">
    Panel Web v2.0
  </div>
</footer>
<!-- ═══ FIN FOOTER ═══ -->


<script>
/* ── SISTEMA DE TEMAS ── */
const THEME_KEY = 'sshplus_theme';
const VALID_THEMES = ['dark', 'light', 'paper', 'gaming'];

function applyTheme(theme) {
    if (!VALID_THEMES.includes(theme)) theme = 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.themeSet === theme);
    });
}

(function(){
    const saved = localStorage.getItem(THEME_KEY) || 'dark';
    applyTheme(saved);
})();

document.addEventListener('click', function(e) {
    const btn = e.target.closest('.theme-btn');
    if (btn && btn.dataset.themeSet) {
        applyTheme(btn.dataset.themeSet);
    }
});

/* ── LÓGICA DEL PANEL ── */
<?php if ($auth): ?>
let allUsers = [];
let currentFilter = 'all';
let globalToken = '';
let globalIP = '';

/* ── DROPDOWN ── */
function toggleDropdown(e) {
    e.stopPropagation();
    const wrap = document.getElementById('dropdown-create');
    wrap.classList.toggle('open');
}

function closeDropdown() {
    const wrap = document.getElementById('dropdown-create');
    if (wrap) wrap.classList.remove('open');
}

// Cerrar al hacer clic fuera
document.addEventListener('click', function(e) {
    const wrap = document.getElementById('dropdown-create');
    if (wrap && !wrap.contains(e.target)) {
        wrap.classList.remove('open');
    }
});

// Cerrar con ESC
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeDropdown();
});

// Abrir modal Usuario Normal
function openCreateUser() {
    closeDropdown();
    openModal('modal-create');
}

// Abrir modal Token
function openCreateToken() {
    closeDropdown();
    openTokenModal();
}

/* ── API ── */
function validatePassForm() {
    const cur = document.getElementById('cp-current').value;
    const n1  = document.getElementById('cp-new').value;
    const n2  = document.getElementById('cp-new2').value;
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
        closeModal('modal-create'); loadUsers(); showToast(r.msg);
        document.getElementById('c-user').value = '';
        document.getElementById('c-pass').value = '';
    } else showToast(r.msg, 'err');
}

async function openTokenModal() {
    try {
        const r = await fetch('?token_info=1').then(x => x.json());
        globalToken = r.token; globalIP = r.ip;
        document.getElementById('token-val').textContent = r.token;
        document.getElementById('token-form').style.display = 'block';
        document.getElementById('token-result').style.display = 'none';
        document.getElementById('t-user').value = '';
        openModal('modal-token');
    } catch(e) { showToast('Error al cargar token', 'err'); }
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

function copyToken() { navigator.clipboard.writeText(globalToken).then(() => showToast('Token copiado')); }
function copyResult() {
    const text = `IP: ${document.getElementById('r-ip').textContent}\nToken: ${document.getElementById('r-token').textContent}\nExpira em: ${document.getElementById('r-expiry').textContent}\nLímite de conexión: ${document.getElementById('r-limit').textContent}`;
    navigator.clipboard.writeText(text).then(() => showToast('Datos copiados'));
}
function resetTokenModal() {
    document.getElementById('token-form').style.display = 'block';
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
    const user = document.getElementById('e-user').value;
    const pass = document.getElementById('e-pass').value;
    const days = document.getElementById('e-days').value;
    const limit = document.getElementById('e-limit').value;
    if (pass) await api({ action: 'change_pass', username: user, password: pass });
    await api({ action: 'change_expiry', username: user, days });
    await api({ action: 'change_limit', username: user, limit });
    closeModal('modal-edit'); loadUsers(); showToast('Usuario actualizado');
}

function openDel(user) {
    document.getElementById('d-user').value = user;
    document.getElementById('d-name').textContent = user;
    openModal('modal-del');
}

async function deleteUser() {
    const user = document.getElementById('d-user').value;
    const r = await api({ action: 'delete', username: user });
    closeModal('modal-del'); loadUsers(); showToast(r.msg);
}

function confirmDeleteExpired() {
    const expired = allUsers.filter(u => u.status === 'expired');
    if (!expired.length) return showToast('No hay usuarios expirados', 'err');
    document.getElementById('exp-count').textContent = expired.length;
    openModal('modal-del-exp');
}

async function deleteExpired() {
    const r = await api({ action: 'delete_expired' });
    closeModal('modal-del-exp'); loadUsers(); showToast(r.msg);
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

loadUsers(); loadOnline(); loadMonitor();
setInterval(loadOnline, 10000);
setInterval(loadMonitor, 5000);
<?php endif; ?>


</script>

</body>
</html>