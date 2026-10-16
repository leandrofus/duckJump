package ui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/leandrofus/duckjump/assist-ui/internal/agent"
	"github.com/leandrofus/duckjump/assist-ui/internal/api"
	"github.com/leandrofus/duckjump/assist-ui/internal/auth"
)

// AssistApp represents the complete Fyne desktop client application.
type AssistApp struct {
	app    fyne.App
	window fyne.Window

	identity auth.UserIdentity
	runner   *agent.Runner

	currentSession *api.SupportSessionDTO
	activeTicker   *time.Ticker
	sessionStart   time.Time
	mu             sync.Mutex

	// UI containers
	mainContainer    *fyne.Container
	formContainer    *fyne.Container
	sessionContainer *fyne.Container

	// Widgets
	entryServer  *widget.Entry
	entryUser    *widget.Entry
	entryReason  *widget.Entry
	entryTicket  *widget.Entry
	accountRadio *widget.RadioGroup
	ssoButton    *widget.Button
	statusBadge  *widget.Label

	// Session widgets
	codeLabel    *widget.Label
	sessionState *widget.Label
	timerLabel   *widget.Label
	infoLabel    *widget.Label
}

// NewAssistApp initializes the application with detected identity and custom theme.
func NewAssistApp() *AssistApp {
	a := app.NewWithID("com.duckjump.assist")
	a.Settings().SetTheme(newDuckJumpTheme())

	w := a.NewWindow("🦆 duckJump Assist — Asistencia Remota")
	w.Resize(fyne.NewSize(580, 680))
	w.CenterOnScreen()

	id := auth.DetectIdentity()
	aApp := &AssistApp{
		app:      a,
		window:   w,
		identity: id,
		runner:   agent.NewRunner(),
	}

	aApp.setupUI()
	return aApp
}

// Run starts the Fyne event loop.
func (a *AssistApp) Run() {
	a.window.ShowAndRun()
}

func (a *AssistApp) setupUI() {
	// Top Branding
	logoTitle := widget.NewLabelWithStyle("🦆 duckJump Assist", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	subTitle := widget.NewLabelWithStyle("Asistencia Remota A Demanda — Control Atendido", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	// User Identity Context Badge
	var idText string
	if a.identity.AccountType == auth.AccountAD {
		idText = fmt.Sprintf("🏢 Dominio AD: %s | Usuario: %s", a.identity.Domain, a.identity.Username)
	} else {
		idText = fmt.Sprintf("💻 Equipo Local: %s | Usuario: %s", a.identity.Hostname, a.identity.Username)
	}
	a.statusBadge = widget.NewLabelWithStyle(idText, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	headerBox := container.NewVBox(
		logoTitle,
		subTitle,
		widget.NewSeparator(),
		a.statusBadge,
		widget.NewSeparator(),
	)

	// Tab 1: Request Support Form
	a.entryServer = widget.NewEntry()
	a.entryServer.SetText("http://127.0.0.1:8088")
	a.entryServer.SetPlaceHolder("http://servidor:8088")

	a.accountRadio = widget.NewRadioGroup([]string{"Cuenta Local", "Active Directory (AD)", "SSO Corporativo"}, func(s string) {
		a.onAccountTypeChanged(s)
	})
	if a.identity.AccountType == auth.AccountAD {
		a.accountRadio.SetSelected("Active Directory (AD)")
	} else {
		a.accountRadio.SetSelected("Cuenta Local")
	}

	a.entryUser = widget.NewEntry()
	a.entryUser.SetText(a.identity.FullTargetName())
	a.entryUser.SetPlaceHolder("Usuario solicitante")

	a.ssoButton = widget.NewButton("🔐 Iniciar Sesión con SSO Corporativo", func() {
		a.triggerSSOLogin()
	})
	a.ssoButton.Hide()

	a.entryReason = widget.NewEntry()
	a.entryReason.SetPlaceHolder("Describa brevemente el problema (ej: Fallo al abrir VPN)")

	a.entryTicket = widget.NewEntry()
	a.entryTicket.SetPlaceHolder("Opcional (ej: INC-2849)")

	reqBtn := widget.NewButton("🚀 Solicitar Asistencia Remota", func() {
		a.onRequestSupport()
	})
	reqBtn.Importance = widget.HighImportance

	requestForm := container.NewVBox(
		widget.NewLabelWithStyle("1. Servidor DuckJump:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		a.entryServer,
		widget.NewLabelWithStyle("2. Tipo de Autenticación / Cuenta:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		a.accountRadio,
		a.ssoButton,
		widget.NewLabelWithStyle("3. Nombre de Usuario:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		a.entryUser,
		widget.NewLabelWithStyle("4. Motivo de la Asistencia:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		a.entryReason,
		widget.NewLabelWithStyle("5. Nro. de Ticket / Incidencia:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		a.entryTicket,
		widget.NewSeparator(),
		reqBtn,
	)

	// Tab 2: Join with Invitation Code / Token
	entryToken := widget.NewEntry()
	entryToken.SetPlaceHolder("Pegue el token recibido o enlace de soporte")

	joinBtn := widget.NewButton("🔗 Conectar Asistencia", func() {
		raw := strings.TrimSpace(entryToken.Text)
		if raw == "" {
			dialog.ShowError(fmt.Errorf("por favor ingrese un código o token"), a.window)
			return
		}
		token := raw
		if strings.Contains(raw, "/join/") {
			parts := strings.Split(raw, "/join/")
			if len(parts) > 1 {
				token = parts[1]
			}
		}
		a.startSupportSession(a.entryServer.Text, token, "")
	})
	joinBtn.Importance = widget.HighImportance

	joinForm := container.NewVBox(
		widget.NewLabel("Si el equipo de soporte técnico ya le generó un enlace o código de invitación, ingréselo aquí:"),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Token o Enlace de Invitación:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		entryToken,
		widget.NewSeparator(),
		joinBtn,
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Solicitar Soporte", requestForm),
		container.NewTabItem("Unirse con Código", joinForm),
	)

	a.formContainer = container.NewVBox(tabs)
	a.setupSessionView()

	a.mainContainer = container.NewVBox(
		headerBox,
		a.formContainer,
	)

	a.window.SetContent(container.NewPadded(a.mainContainer))
}

func (a *AssistApp) setupSessionView() {
	codeTitle := widget.NewLabelWithStyle("CÓDIGO DE VERIFICACIÓN", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	a.codeLabel = widget.NewLabelWithStyle("[ ------ ]", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	a.codeLabel.Wrapping = fyne.TextWrapOff

	codeExplain := widget.NewLabelWithStyle("Informe este código a su técnico de soporte para autorizar el acceso.", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	copyBtn := widget.NewButton("📋 Copiar Código", func() {
		code := strings.Trim(a.codeLabel.Text, "[ ]")
		a.window.Clipboard().SetContent(code)
		dialog.ShowInformation("Copiado", "Código copiado al portapapeles", a.window)
	})

	codeCard := container.NewVBox(
		codeTitle,
		a.codeLabel,
		codeExplain,
		container.NewCenter(copyBtn),
	)

	a.sessionState = widget.NewLabelWithStyle("🟡 Conectando con el técnico...", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	a.timerLabel = widget.NewLabelWithStyle("Tiempo de sesión: 00:00", fyne.TextAlignCenter, fyne.TextStyle{})
	a.infoLabel = widget.NewLabel("")

	stopBtn := widget.NewButton("🛑 Finalizar Asistencia y Desconectar", func() {
		a.onStopSession()
	})
	stopBtn.Importance = widget.DangerImportance

	a.sessionContainer = container.NewVBox(
		widget.NewSeparator(),
		codeCard,
		widget.NewSeparator(),
		a.sessionState,
		a.timerLabel,
		a.infoLabel,
		widget.NewSeparator(),
		stopBtn,
	)
}

func (a *AssistApp) onAccountTypeChanged(choice string) {
	switch choice {
	case "SSO Corporativo":
		a.ssoButton.Show()
		a.entryUser.SetPlaceHolder("Se completará al autenticar con SSO")
	case "Active Directory (AD)":
		a.ssoButton.Hide()
		if a.identity.AccountType == auth.AccountAD {
			a.entryUser.SetText(a.identity.FullTargetName())
		}
	default:
		a.ssoButton.Hide()
		a.entryUser.SetText(a.identity.Username)
	}
}

func (a *AssistApp) triggerSSOLogin() {
	serverURL := strings.TrimSpace(a.entryServer.Text)
	if serverURL == "" {
		dialog.ShowError(fmt.Errorf("ingrese la URL del servidor"), a.window)
		return
	}

	progress := dialog.NewCustom("Iniciando SSO", "Cancelar", widget.NewLabel("Abriendo navegador para autenticación corporativa..."), a.window)
	progress.Show()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	go func() {
		defer progress.Hide()
		defer cancel()

		client := api.NewClient(serverURL)
		providers, err := client.GetAuthProviders(ctx)
		if err != nil {
			dialog.ShowError(fmt.Errorf("no se pudo verificar SSO en el servidor: %w", err), a.window)
			return
		}
		if providers.OIDC == nil {
			dialog.ShowInformation("SSO no configurado", "El servidor no tiene habilitado un proveedor SSO/OIDC.", a.window)
			return
		}

		res, err := auth.LaunchSSO(ctx, serverURL, providers.OIDC.LoginURL)
		if err != nil {
			dialog.ShowError(fmt.Errorf("error durante SSO: %w", err), a.window)
			return
		}

		a.identity.AccountType = auth.AccountSSO
		if res.Username != "" {
			a.identity.Username = res.Username
		}
		if res.Email != "" {
			a.identity.Username = res.Email
		}
		a.entryUser.SetText(a.identity.Username)
		a.statusBadge.SetText(fmt.Sprintf("🔑 SSO: %s", a.identity.Username))
		dialog.ShowInformation("Éxito", "Autenticación SSO corporativa completada.", a.window)
	}()
}

func (a *AssistApp) onRequestSupport() {
	serverURL := strings.TrimSpace(a.entryServer.Text)
	user := strings.TrimSpace(a.entryUser.Text)
	reason := strings.TrimSpace(a.entryReason.Text)
	ticket := strings.TrimSpace(a.entryTicket.Text)

	if serverURL == "" || user == "" {
		dialog.ShowError(fmt.Errorf("el servidor y el usuario son requeridos"), a.window)
		return
	}

	accType := string(auth.AccountLocal)
	if a.accountRadio.Selected == "Active Directory (AD)" {
		accType = string(auth.AccountAD)
	} else if a.accountRadio.Selected == "SSO Corporativo" {
		accType = string(auth.AccountSSO)
	}

	client := api.NewClient(serverURL)
	req := api.RequestSupportReq{
		TargetName:  user,
		Reason:      reason,
		Ticket:      ticket,
		AccountType: accType,
		Domain:      a.identity.Domain,
		Hostname:    a.identity.Hostname,
		ClientOS:    a.identity.OS,
	}

	progress := dialog.NewCustom("Solicitando Soporte", "Cancelar", widget.NewLabel("Registrando solicitud en la central de asistencia..."), a.window)
	progress.Show()

	go func() {
		defer progress.Hide()
		sess, err := client.RequestSupport(context.Background(), req)
		if err != nil {
			dialog.ShowError(fmt.Errorf("falla al solicitar soporte: %w", err), a.window)
			return
		}

		a.currentSession = sess
		a.startSupportSession(serverURL, sess.Token, sess.VerificationCode)
	}()
}

func (a *AssistApp) startSupportSession(serverURL, token, initialCode string) {
	a.mu.Lock()
	a.sessionStart = time.Now()
	a.mu.Unlock()

	// Switch UI to Session view
	a.mainContainer.Objects = []fyne.CanvasObject{
		a.mainContainer.Objects[0], // header
		a.sessionContainer,
	}
	a.mainContainer.Refresh()

	if initialCode != "" {
		a.codeLabel.SetText(fmt.Sprintf("[ %s ]", initialCode))
	} else {
		a.codeLabel.SetText("[ Buscando... ]")
	}

	a.sessionState.SetText("🟡 Conectando con la central...")
	a.infoLabel.SetText(fmt.Sprintf("Servidor: %s\nToken: %s", serverURL, token[:min(len(token), 8)]+"..."))

	// Setup agent runner listeners
	a.runner.OnCode = func(code string) {
		a.codeLabel.SetText(fmt.Sprintf("[ %s ]", code))
	}

	a.runner.OnConnected = func() {
		a.sessionState.SetText("🟢 ¡Técnico Conectado! Asistencia en curso.")
	}

	a.runner.OnExit = func(err error) {
		a.sessionState.SetText("⚪ Sesión finalizada.")
	}

	// Start agent process
	go func() {
		err := a.runner.Start(context.Background(), serverURL, token)
		if err != nil {
			dialog.ShowError(fmt.Errorf("error al ejecutar agente: %w", err), a.window)
			a.onStopSession()
		}
	}()

	// Polling session status and timer
	a.activeTicker = time.NewTicker(1 * time.Second)
	go func() {
		client := api.NewClient(serverURL)
		for range a.activeTicker.C {
			a.mu.Lock()
			elapsed := time.Since(a.sessionStart)
			a.mu.Unlock()

			mins := int(elapsed.Minutes())
			secs := int(elapsed.Seconds()) % 60
			a.timerLabel.SetText(fmt.Sprintf("Tiempo de sesión: %02d:%02d", mins, secs))

			// Check gateway status
			status, err := client.GetStatus(context.Background(), token)
			if err == nil && status != nil {
				if status.Status == "active" {
					a.sessionState.SetText("🟢 ¡Técnico Conectado y Asistiendo!")
				} else if status.Status == "ended" {
					a.onStopSession()
					return
				}
			}
		}
	}()
}

func (a *AssistApp) onStopSession() {
	if a.activeTicker != nil {
		a.activeTicker.Stop()
		a.activeTicker = nil
	}

	a.runner.Stop()

	if a.currentSession != nil {
		client := api.NewClient(a.entryServer.Text)
		_ = client.EndSession(context.Background(), a.currentSession.Token)
		a.currentSession = nil
	}

	// Restore normal form view
	a.mainContainer.Objects = []fyne.CanvasObject{
		a.mainContainer.Objects[0], // header
		a.formContainer,
	}
	a.mainContainer.Refresh()
	dialog.ShowInformation("Asistencia Finalizada", "La sesión de soporte remoto ha concluido con éxito.", a.window)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
