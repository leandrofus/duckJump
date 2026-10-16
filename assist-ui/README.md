# 🦆 duckJump Assist — Desktop Client UI (Fyne)

Interfaz gráfica de escritorio moderna desarrollada con [Fyne](https://fyne.io) para la solicitud y recepción de soporte remoto asistido a demanda a través de **duckJump**.

---

## 🚀 Características Principales

1. **Solicitud y Recepción de Asistencia (A Demanda / Asistido)**:
   - Formulario directo para solicitar soporte técnico al Gateway indicando motivo e incidencia/ticket.
   - Pestaña para **unirse inmediatamente** mediante código de sesión o enlace de invitación (`/join/<token>`).
   - Muestra destacada del **Código de Verificación de 6 dígitos** (`[ 501 986 ]`) con botón de copiado rápido al portapapeles.
   - Supervisión y ejecución automática en segundo plano del motor nativo `duckjump-assist`.
   - Controles de seguridad en tiempo real: **Pausar Control Remoto** y **Finalizar y Desconectar (Emergency Stop)**.

2. **Detección y Soporte de Cuentas**:
   - **Cuentas Locales**: Detección automática del usuario y equipo local en Windows y Linux.
   - **Active Directory (AD)**:
     - Detección automática de dominio corporativo (`USERDOMAIN`, `USERDNSDOMAIN`).
     - Prefijo de identidad `DOMINIO\usuario` y soporte para equipos unidos a dominio.
   - **Single Sign-On (SSO / OIDC)**:
     - Consulta automática de proveedores configurados en el gateway (`/api/v1/auth/providers`).
     - Flujo interactivo abriendo el navegador predeterminado del usuario para autenticar contra Keycloak, Entra ID, Okta o ADFS.
     - Captura automática de credenciales mediante servidor local temporal (`/callback`).

---

## 🛠️ Estructura del Proyecto

```
assist-ui/
├── main.go                     # Punto de entrada
├── Makefile                    # Tareas de compilación y empaquetado
├── go.mod / go.sum
└── internal/
    ├── api/                    # Cliente HTTP para el DuckJump Gateway
    ├── auth/
    │   ├── identity.go         # Detección de cuentas Locales y Active Directory
    │   └── sso.go              # Servidor efímero y flujo interactivo SSO
    ├── agent/
    │   └── runner.go           # Descarga, ejecución y supervisión de duckjump-assist
    └── ui/
        ├── app.go              # Vistas principales Fyne (Solicitud, Código y Sesión)
        └── theme.go            # Tema oscuro con colores de marca DuckJump
```

---

## 📦 Compilación

### Requisitos Previos
- Go 1.22+
- En Linux: paquetes de desarrollo OpenGL y X11 (`libgl1-mesa-dev`, `xorg-dev`).

### Compilación Nativa (Linux / macOS):
```bash
make build
# Genera bin/duckjump-assist-ui
```

### Compilación para Windows (x86_64):
```bash
make build-windows
# Genera bin/duckjump-assist-ui.exe
```

### Compilación mediante Docker (sin necesidad de dependencias en el host):
```bash
make docker-build-linux
```
