package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// AuthProvidersResponse represents the available authentication methods.
type AuthProvidersResponse struct {
	Local bool `json:"local"`
	OIDC  *struct {
		Name     string `json:"name"`
		LoginURL string `json:"login_url"`
	} `json:"oidc"`
}

// RequestSupportReq represents a payload to request assistance.
type RequestSupportReq struct {
	TargetName  string `json:"target_name"`
	Reason      string `json:"reason"`
	Ticket      string `json:"ticket"`
	AccountType string `json:"account_type"`
	Domain      string `json:"domain"`
	Hostname    string `json:"hostname"`
	ClientOS    string `json:"client_os"`
}

// SupportSessionDTO represents a created assistance session.
type SupportSessionDTO struct {
	ID               string    `json:"id"`
	Token            string    `json:"token"`
	JoinURL          string    `json:"join_url"`
	TargetName       string    `json:"target_name"`
	Reason           string    `json:"reason"`
	Ticket           string    `json:"ticket"`
	TotpSecret       string    `json:"totp_secret"`
	VerificationCode string    `json:"verification_code"`
	Status           string    `json:"status"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// SupportStatusDTO represents the current live status of a support session.
type SupportStatusDTO struct {
	ID             string     `json:"id"`
	Token          string     `json:"token"`
	Status         string     `json:"status"`
	TargetName     string     `json:"target_name"`
	Reason         string     `json:"reason"`
	Ticket         string     `json:"ticket"`
	ClientHostname string     `json:"client_hostname"`
	ClientOS       string     `json:"client_os"`
	ConnectedAt    *time.Time `json:"connected_at"`
	ActivatedAt    *time.Time `json:"activated_at"`
	EndedAt        *time.Time `json:"ended_at"`
}

// Client wraps HTTP communication with the duckJump Gateway.
type Client struct {
	BaseURL    string
	httpClient *http.Client
}

// NewClient creates a new Gateway client.
func NewClient(baseURL string) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: 15 * time.Second,
		},
	}
}

// SetToken sets the bearer/session token in the client cookies.
func (c *Client) SetToken(token string) {
	if token == "" {
		return
	}
	u, err := url.Parse(c.BaseURL)
	if err == nil {
		c.httpClient.Jar.SetCookies(u, []*http.Cookie{
			{Name: "duckjump_session", Value: token, Path: "/"},
		})
	}
}

// GetAuthProviders retrieves the login methods configured on the gateway.
func (c *Client) GetAuthProviders(ctx context.Context) (*AuthProvidersResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/api/v1/auth/providers", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error al conectar con el servidor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("servidor respondió con código %d: %s", resp.StatusCode, string(b))
	}

	var res AuthProvidersResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Login authenticates a local or Active Directory account on the gateway.
func (c *Client) Login(ctx context.Context, username, password string) error {
	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/v1/auth/login", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error al iniciar sesión: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("credenciales inválidas o error de autenticación (%d): %s", resp.StatusCode, string(b))
	}
	return nil
}

// RequestSupport submits a support session request to the gateway.
func (c *Client) RequestSupport(ctx context.Context, data RequestSupportReq) (*SupportSessionDTO, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/v1/support/request", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error de red al solicitar soporte: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error del servidor (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var sess SupportSessionDTO
	if err := json.Unmarshal(bodyBytes, &sess); err != nil {
		return nil, fmt.Errorf("respuesta inválida: %w", err)
	}
	if sess.VerificationCode == "" && sess.TotpSecret != "" {
		sess.VerificationCode = sess.TotpSecret
	}
	return &sess, nil
}

// GetStatus checks the live status of the support session.
func (c *Client) GetStatus(ctx context.Context, token string) (*SupportStatusDTO, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/api/v1/support/status/"+token, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("código %d: %s", resp.StatusCode, string(b))
	}

	var status SupportStatusDTO
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return &status, nil
}

// EndSession requests termination of the support session.
func (c *Client) EndSession(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/v1/support/end/"+token, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
