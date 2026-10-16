package server

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ServeSupportJoin serves either the public HTML landing page or JSON metadata for the support link.
func (s *Server) ServeSupportJoin(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	sess, err := s.Store.Q.GetSupportSessionByToken(r.Context(), token)
	if err != nil {
		http.Error(w, "Enlace de asistencia no válido o expirado", http.StatusNotFound)
		return
	}

	now := time.Now()
	expired := now.After(sess.ExpiresAt)
	status := sess.Status
	if expired && status == "pending" {
		status = "expired"
	}

	_, _, baseURL, _ := s.siteURLs(r)
	if baseURL == "" {
		scheme := "http"
		if s.secureRequest(r) {
			scheme = "https"
		}
		baseURL = scheme + "://" + r.Host
	}
	baseURL = strings.TrimRight(baseURL, "/")

	launchScriptURL := fmt.Sprintf("%s/support/launch.sh?token=%s", baseURL, token)
	ps1ScriptURL := fmt.Sprintf("%s/support/run.ps1?token=%s", baseURL, token)
	downloadBinaryURL := fmt.Sprintf("%s/support/duckjump-assist", baseURL)
	agentServerWS := fmt.Sprintf("%s/api/v1/support/agent-tunnel/%s", baseURL, token)

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		dto := s.toSupportSessionDTO(sess)
		_ = ok(w, map[string]any{
			"session":             dto,
			"agent_server":        agentServerWS,
			"download_binary_url": downloadBinaryURL,
			"launch_script_url":   launchScriptURL,
			"run_ps1_url":         ps1ScriptURL,
			"curl_command":        fmt.Sprintf("curl -fsSL %s | sh", launchScriptURL),
			"ps1_command":         fmt.Sprintf("irm %s | iex", ps1ScriptURL),
			"manual_command":      fmt.Sprintf("./duckjump-assist --server %s --token %s", baseURL, token),
		})
		return
	}

	// Render responsive HTML landing page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	targetName := html.EscapeString(sess.TargetName)
	reason := html.EscapeString(sess.Reason)
	ticket := html.EscapeString(sess.Ticket)
	expiresFormatted := sess.ExpiresAt.Format("02/01/2006 15:04:05 MST")

	statusBadge := `<span class="badge badge-warning">Esperando Conexión</span>`
	var statusAlertHtml string
	switch status {
	case "connected":
		statusBadge = `<span class="badge badge-info">Conectado (Requiere Código)</span>`
	case "active":
		statusBadge = `<span class="badge badge-success">Sesión Activa</span>`
	case "ended":
		statusBadge = `<span class="badge badge-secondary">Sesión Finalizada</span>`
		statusAlertHtml = `<div class="security-callout" style="background: rgba(239, 68, 68, 0.12); border-color: rgba(239, 68, 68, 0.35);">
      <div class="icon">⚠️</div>
      <div>
        <h3 style="color: #f87171;">Esta sesión de asistencia ya fue finalizada</h3>
        <p>Por seguridad, los enlaces y códigos de verificación son de un solo uso. Si aún requiere asistencia remota, solicite a su operador un nuevo enlace.</p>
      </div>
    </div>`
	case "expired":
		statusBadge = `<span class="badge badge-danger">Enlace Caducado</span>`
		statusAlertHtml = `<div class="security-callout" style="background: rgba(239, 68, 68, 0.12); border-color: rgba(239, 68, 68, 0.35);">
      <div class="icon">⏰</div>
      <div>
        <h3 style="color: #f87171;">El enlace de asistencia ha caducado</h3>
        <p>El tiempo límite de espera para esta sesión ha concluido. Solicite a su operador técnico que genere un nuevo enlace de asistencia.</p>
      </div>
    </div>`
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Asistencia Remota — duckJump Assist</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🦆</text></svg>">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111927;
      --card-border: #1f293d;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: #f59e0b;
      --primary-hover: #d97706;
      --code-bg: #060911;
      --code-border: #222f46;
      --radius: 10px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 32px 16px;
    }
    .container {
      width: 100%%;
      max-width: 720px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .header {
      text-align: center;
      margin-bottom: 8px;
    }
    .logo {
      font-size: 48px;
      margin-bottom: 8px;
      display: inline-block;
    }
    .header h1 {
      font-size: 26px;
      font-weight: 700;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
    }
    .header p {
      color: var(--text-muted);
      font-size: 15px;
      margin-top: 4px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius);
      padding: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }
    .session-info {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-top: 12px;
      padding-top: 16px;
      border-top: 1px solid var(--card-border);
      font-size: 14px;
    }
    .info-label {
      color: var(--text-muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 2px;
    }
    .info-val {
      font-weight: 600;
      word-break: break-all;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
    }
    .badge-warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-info { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-success { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-secondary { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }
    
    .security-callout {
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.25);
      border-radius: var(--radius);
      padding: 16px 20px;
      display: flex;
      gap: 14px;
      align-items: flex-start;
    }
    .security-callout .icon {
      font-size: 22px;
      flex-shrink: 0;
    }
    .security-callout h3 {
      font-size: 14px;
      font-weight: 600;
      color: #34d399;
      margin-bottom: 4px;
    }
    .security-callout p {
      font-size: 13px;
      color: #cbd5e1;
      margin: 0;
    }

    .tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 8px;
    }
    .tab-btn {
      background: none;
      border: none;
      color: var(--text-muted);
      padding: 6px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.15s ease;
    }
    .tab-btn.active {
      background: rgba(245, 158, 11, 0.15);
      color: var(--primary);
    }
    .tab-btn:hover:not(.active) {
      color: var(--text);
      background: rgba(255, 255, 255, 0.05);
    }
    .tab-content {
      display: none;
    }
    .tab-content.active {
      display: block;
    }

    .code-block {
      background: var(--code-bg);
      border: 1px solid var(--code-border);
      border-radius: 8px;
      padding: 14px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin: 10px 0 16px 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
      overflow-x: auto;
    }
    .code-block code {
      white-space: nowrap;
      overflow-x: auto;
    }
    .copy-btn {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
      border: 1px solid var(--card-border);
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      flex-shrink: 0;
      transition: all 0.2s;
    }
    .copy-btn:hover {
      background: rgba(255, 255, 255, 0.15);
      border-color: rgba(255, 255, 255, 0.25);
    }
    .copy-btn.copied {
      background: #10b981;
      color: #fff;
      border-color: #10b981;
    }

    .btn-download {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: var(--primary);
      color: #0b0f19;
      font-weight: 600;
      font-size: 14px;
      padding: 12px 24px;
      border-radius: 8px;
      text-decoration: none;
      transition: background 0.15s ease;
      cursor: pointer;
      border: none;
    }
    .btn-download:hover {
      background: var(--primary-hover);
    }

    .steps {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-top: 14px;
    }
    .step-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      font-size: 14px;
    }
    .step-num {
      width: 24px;
      height: 24px;
      border-radius: 50%%;
      background: rgba(245, 158, 11, 0.2);
      color: var(--primary);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      font-weight: 700;
      flex-shrink: 0;
    }
    .footer {
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 16px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">🦆</div>
      <h1>duckJump Assist</h1>
      <p>Sesión de Asistencia Remota A Demanda</p>
    </div>

    %s

    <!-- Security Guarantee Banner -->
    <div class="security-callout">
      <div class="icon">🛡️</div>
      <div>
        <h3>Asistencia Estrictamente Asistida y Segura</h3>
        <p>Esta conexión requiere su autorización presencial. Nadie puede acceder a su equipo de forma desatendida. Al iniciar el agente, verá en su pantalla un código de 6 dígitos que deberá dictar a su operador. Usted conserva la prioridad de su teclado y ratón en todo momento.</p>
      </div>
    </div>

    <!-- Session Details Card -->
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2 style="font-size: 18px; font-weight: 600;">Detalles de la Solicitud</h2>
        %s
      </div>
      <div class="session-info">
        <div>
          <div class="info-label">Usuario / Equipo</div>
          <div class="info-val">%s</div>
        </div>
        %s
        %s
        <div>
          <div class="info-label">Expira en</div>
          <div class="info-val">%s</div>
        </div>
      </div>
    </div>

    <!-- Instructions & Launch Options Card -->
    <div class="card">
      <h2 style="font-size: 18px; font-weight: 600; margin-bottom: 14px;">Cómo Conectar su Equipo</h2>
      
      <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('tab-terminal')">🚀 Terminal / Un Comando (Recomendado)</button>
        <button class="tab-btn" onclick="switchTab('tab-download')">📥 Descarga Manual</button>
      </div>

      <!-- Tab 1: Terminal Launcher (Linux / Mac / Windows) -->
      <div id="tab-terminal" class="tab-content active">
        <p style="font-size: 14px; color: var(--text-muted); margin-bottom: 8px;">
          Copie y ejecute este comando en su terminal. Descargará y ejecutará el agente temporalmente sin dejar archivos residuales:
        </p>

        <!-- Subtabs OS -->
        <div style="display: flex; gap: 6px; margin: 10px 0 6px 0;">
          <button id="btn-linux" class="tab-btn active" style="font-size: 12px; padding: 4px 10px;" onclick="switchOS('linux')">Linux / macOS (Bash)</button>
          <button id="btn-win" class="tab-btn" style="font-size: 12px; padding: 4px 10px;" onclick="switchOS('windows')">Windows (PowerShell)</button>
        </div>

        <div id="cmd-linux" class="code-block">
          <code>curl -fsSL %s | sh</code>
          <button class="copy-btn" onclick="copyText('curl -fsSL %s | sh', this)">📋 Copiar</button>
        </div>

        <div id="cmd-windows" class="code-block" style="display: none;">
          <code>irm %s | iex</code>
          <button class="copy-btn" onclick="copyText('irm %s | iex', this)">📋 Copiar</button>
        </div>
      </div>

      <!-- Tab 2: Manual Download -->
      <div id="tab-download" class="tab-content">
        <p style="font-size: 14px; color: var(--text-muted); margin-bottom: 14px;">
          Descargue directamente el ejecutable del agente ligero duckJump Assist para su sistema:
        </p>
        <div style="margin-bottom: 18px;">
          <a href="%s" class="btn-download">
            📥 Descargar duckjump-assist (Linux x86_64)
          </a>
        </div>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 6px;">
          Una vez descargado, otorgue permisos y ejecútelo con este comando preconfigurado:
        </p>
        <div class="code-block">
          <code>chmod +x duckjump-assist && ./duckjump-assist --server %s --token %s</code>
          <button class="copy-btn" onclick="copyText('chmod +x duckjump-assist && ./duckjump-assist --server %s --token %s', this)">📋 Copiar</button>
        </div>
      </div>

      <!-- Next steps checklist -->
      <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--card-border);">
        <h3 style="font-size: 15px; font-weight: 600; margin-bottom: 10px;">Pasos siguientes:</h3>
        <div class="steps">
          <div class="step-item">
            <div class="step-num">1</div>
            <div>Ejecute el comando en su terminal o abra la aplicación descargada.</div>
          </div>
          <div class="step-item">
            <div class="step-num">2</div>
            <div>Aparecerá en su pantalla un banner con un <strong>Código de Verificación de 6 dígitos</strong>.</div>
          </div>
          <div class="step-item">
            <div class="step-num">3</div>
            <div>Díctele este código a su operador técnico para autorizar el inicio de la sesión.</div>
          </div>
          <div class="step-item">
            <div class="step-num">4</div>
            <div>Para desconectar en cualquier momento, presione <strong>Ctrl+C</strong> o cierre la ventana.</div>
          </div>
        </div>
      </div>
    </div>

    <div class="footer">
      duckJump Gateway &bull; Asistencia Remota Segura A Demanda
    </div>
  </div>

  <script>
    function copyText(text, btn) {
      function onCopied() {
        const orig = btn.innerHTML;
        btn.innerHTML = '✅ ¡Copiado!';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.innerHTML = orig;
          btn.classList.remove('copied');
        }, 2000);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(onCopied).catch(() => fallbackCopy(text, onCopied));
      } else {
        fallbackCopy(text, onCopied);
      }
    }

    function fallbackCopy(text, cb) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try {
        document.execCommand('copy');
        cb();
      } catch (e) {}
      document.body.removeChild(ta);
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(b => {
        if (b.getAttribute('onclick') && b.getAttribute('onclick').includes('switchTab')) {
          b.classList.remove('active');
        }
      });
      event.target.classList.add('active');
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
    }

    function switchOS(os) {
      const btnLinux = document.getElementById('btn-linux');
      const btnWin = document.getElementById('btn-win');
      const cmdLinux = document.getElementById('cmd-linux');
      const cmdWin = document.getElementById('cmd-windows');

      if (os === 'linux') {
        btnLinux.classList.add('active');
        btnWin.classList.remove('active');
        cmdLinux.style.display = 'flex';
        cmdWin.style.display = 'none';
      } else {
        btnWin.classList.add('active');
        btnLinux.classList.remove('active');
        cmdWin.style.display = 'flex';
        cmdLinux.style.display = 'none';
      }
    }
  </script>
</body>
</html>`,
		statusAlertHtml,
		statusBadge,
		targetName,
		ticketHtml(ticket),
		reasonHtml(reason),
		expiresFormatted,
		launchScriptURL, launchScriptURL,
		ps1ScriptURL, ps1ScriptURL,
		downloadBinaryURL,
		baseURL, token,
		baseURL, token,
	)

	_, _ = w.Write([]byte(htmlContent))
}

func ticketHtml(ticket string) string {
	if ticket == "" {
		return ""
	}
	return fmt.Sprintf(`<div><div class="info-label">Ticket</div><div class="info-val">%s</div></div>`, ticket)
}

func reasonHtml(reason string) string {
	if reason == "" {
		return ""
	}
	return fmt.Sprintf(`<div><div class="info-label">Motivo</div><div class="info-val">%s</div></div>`, reason)
}

// DownloadAssistAgent serves the compiled duckjump-assist binary.
func (s *Server) DownloadAssistAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	osTarget := r.URL.Query().Get("os")
	path, err := s.findAssistBinary(osTarget)
	if err != nil {
		if osTarget == "windows" {
			http.Error(w, "duckjump-assist.exe para Windows no está disponible en este servidor (solo Linux x86_64 disponible)", http.StatusNotFound)
			return
		}
		writeErr(w, &apiError{http.StatusNotFound, "not_found", err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if osTarget == "windows" || strings.HasSuffix(path, ".exe") {
		w.Header().Set("Content-Disposition", `attachment; filename="duckjump-assist.exe"`)
	} else {
		w.Header().Set("Content-Disposition", `attachment; filename="duckjump-assist"`)
	}
	http.ServeFile(w, r, path)
}

// ServeAssistLaunchScript serves an ephemeral bash launcher for duckjump-assist.
func (s *Server) ServeAssistLaunchScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _, baseURL, _ := s.siteURLs(r)
	if baseURL == "" {
		scheme := "http"
		if s.secureRequest(r) {
			scheme = "https"
		}
		baseURL = scheme + "://" + r.Host
	}
	baseURL = strings.TrimRight(baseURL, "/")

	token := r.URL.Query().Get("token")
	server := r.URL.Query().Get("server")
	if server == "" {
		server = baseURL
	}
	binURL := r.URL.Query().Get("bin_url")
	if binURL == "" {
		binURL = baseURL + "/support/duckjump-assist"
	}

	script := generateAssistLaunchScript(token, server, binURL)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(script))
}

// ServeAssistPowerShellScript serves an ephemeral PowerShell launcher for duckjump-assist on Windows.
func (s *Server) ServeAssistPowerShellScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _, baseURL, _ := s.siteURLs(r)
	if baseURL == "" {
		scheme := "http"
		if s.secureRequest(r) {
			scheme = "https"
		}
		baseURL = scheme + "://" + r.Host
	}
	baseURL = strings.TrimRight(baseURL, "/")

	token := r.URL.Query().Get("token")
	server := r.URL.Query().Get("server")
	if server == "" {
		server = baseURL
	}
	binURL := r.URL.Query().Get("bin_url")
	if binURL == "" {
		binURL = baseURL + "/support/duckjump-assist?os=windows"
	}

	script := fmt.Sprintf(`param(
    [string]$Token = %s,
    [string]$Server = %s,
    [string]$BinUrl = %s
)

if (-not $Token) {
    Write-Error "Session token is required"
    Write-Host ""
    Write-Host "Presione Enter para salir..." -ForegroundColor Gray
    try { Read-Host } catch {}
    exit 1
}

$tempDir = Join-Path $env:TEMP ("duckjump-assist-" + [System.Guid]::NewGuid().ToString().Substring(0,8))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$tempBin = Join-Path $tempDir "duckjump-assist.exe"

try {
    Write-Host "==> Descargando agente duckJump Assist..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $BinUrl -OutFile $tempBin -ErrorAction Stop

    # Verificar si es un ejecutable PE de Windows valido (empieza con 'MZ')
    $bytes = [System.IO.File]::ReadAllBytes($tempBin)
    if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        Write-Host ""
        Write-Host "[!] Error: duckjump-assist.exe para Windows no esta compilado en este servidor." -ForegroundColor Red
        Write-Host "    El servidor actualmente solo tiene disponible el agente para Linux (x86_64)." -ForegroundColor Yellow
        Write-Host "    Para conectarse a la asistencia, por favor ejecute el comando en un equipo Linux:" -ForegroundColor Cyan
        Write-Host "    curl -fsSL $Server/support/launch.sh?token=$Token | sh" -ForegroundColor White
        Write-Host ""
        Write-Host "Presione Enter para salir..." -ForegroundColor Gray
        try { Read-Host } catch {}
        exit 1
    }

    Write-Host "==> Iniciando duckJump Assist..." -ForegroundColor Green
    & $tempBin --server $Server --token $Token
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "duckJump Assist finalizo con codigo $LASTEXITCODE." -ForegroundColor Yellow
        Write-Host "Presione Enter para salir..." -ForegroundColor Gray
        try { Read-Host } catch {}
    }
} catch {
    Write-Host ""
    Write-Host "[!] Error: duckjump-assist.exe para Windows no esta disponible en el servidor." -ForegroundColor Red
    Write-Host "    Detalle: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    El servidor actualmente solo tiene disponible el agente para Linux (x86_64)." -ForegroundColor Yellow
    Write-Host "    Para conectarse a la asistencia, ejecute en Linux: curl -fsSL $Server/support/launch.sh?token=$Token | sh" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Presione Enter para salir..." -ForegroundColor Gray
    try { Read-Host } catch {}
    exit 1
} finally {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
`, psQuote(token), psQuote(server), psQuote(binURL))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(script))
}

func psQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, ``) + `"`
}

func generateAssistLaunchScript(token, server, binURL string) string {
	return fmt.Sprintf(`#!/bin/sh
set -e

# duckJump Assist — Ephemeral Launch Script
# Downloads and executes duckjump-assist without leaving permanent files.

DEFAULT_TOKEN=%s
DEFAULT_SERVER=%s
DEFAULT_BIN_URL=%s

TOKEN="${DUCKJUMP_SUPPORT_TOKEN:-$DEFAULT_TOKEN}"
SERVER="${DUCKJUMP_SUPPORT_SERVER:-$DEFAULT_SERVER}"
BIN_URL="${DUCKJUMP_SUPPORT_BIN_URL:-$DEFAULT_BIN_URL}"

while [ $# -gt 0 ]; do
  case "$1" in
    --token|-t) TOKEN="$2"; shift 2 ;;
    --server|-s) SERVER="$2"; shift 2 ;;
    --bin-url) BIN_URL="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$TOKEN" ]; then
  echo "Error: session token is required (pass via ?token= or --token)" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/duckjump-assist.XXXXXX)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

TMP_BIN="$TMP_DIR/duckjump-assist"

echo "==> Descargando duckJump Assist desde $SERVER..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BIN_URL" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_BIN" "$BIN_URL"
else
  echo "Error: ni curl ni wget están disponibles." >&2
  exit 1
fi

chmod +x "$TMP_BIN"
if [ -n "$WAYLAND_DISPLAY" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
  if ! command -v gst-launch-1.0 >/dev/null 2>&1; then
    echo "ℹ️  Sesión Wayland detectada. Para streaming de pantalla fluido a 60 FPS (PipeWire):"
    echo "    Recomendado: sudo dnf install -y gstreamer1-tools gstreamer1-pipewire   (Fedora/RHEL)"
    echo "                 sudo apt install -y gstreamer1.0-tools gstreamer1.0-pipewire (Ubuntu/Debian)"
    echo ""
  fi
fi

"$TMP_BIN" --server "$SERVER" --token "$TOKEN"
STATUS=$?
cleanup
exit $STATUS
`,
		shQuote(token),
		shQuote(server),
		shQuote(binURL),
	)
}

func (s *Server) findAssistBinary(osTarget string) (string, error) {
	name := "duckjump-assist"
	if osTarget == "windows" {
		name = "duckjump-assist.exe"
	}

	// 1. Next to the running executable
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), name)
		if isFile(p) {
			return p, nil
		}
	}

	// 2. Relative to current working directory or known build locations
	candidates := []string{
		"bin/" + name,
		"dist/bin/" + name,
		"../dist/bin/" + name,
		"duckjumpd/target/release/" + name,
		"../duckjumpd/target/release/" + name,
		"duckjumpd/target/debug/" + name,
		"gateway/bin/" + name,
		"/usr/bin/" + name,
		"/usr/local/bin/" + name,
	}
	for _, c := range candidates {
		if isFile(c) {
			return c, nil
		}
	}

	// 3. System PATH
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("%s binary not found on server", name)
}
