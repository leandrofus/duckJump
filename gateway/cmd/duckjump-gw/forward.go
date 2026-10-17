package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

func forwardCmd(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	serverURL := fs.String("server", os.Getenv("DUCKJUMP_SERVER"), "gateway URL (default: http://127.0.0.1:8088)")
	token := fs.String("token", os.Getenv("DUCKJUMP_TOKEN"), "session or auth token")
	bind := fs.String("bind", "127.0.0.1", "local IP to bind")
	username := fs.String("user", os.Getenv("DUCKJUMP_USER"), "username for login")
	password := fs.String("password", os.Getenv("DUCKJUMP_PASSWORD"), "password for login")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: duckjump forward [flags] <connection> <local-port>[:<remote-port>]\n\nflags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nexample:\n  duckjump forward db-prod 5432\n  duckjump forward -server https://bastion.corp.net db-prod 5432:5432\n")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fs.Usage()
		return fmt.Errorf("missing connection or port specification")
	}

	connName := rest[0]
	portSpec := rest[1]

	var localPort, remotePort int
	if strings.Contains(portSpec, ":") {
		parts := strings.SplitN(portSpec, ":", 2)
		lp, err := strconv.Atoi(parts[0])
		if err != nil || lp <= 0 || lp > 65535 {
			return fmt.Errorf("invalid local port in %q", portSpec)
		}
		rp, err := strconv.Atoi(parts[1])
		if err != nil || rp <= 0 || rp > 65535 {
			return fmt.Errorf("invalid remote port in %q", portSpec)
		}
		localPort = lp
		remotePort = rp
	} else {
		p, err := strconv.Atoi(portSpec)
		if err != nil || p <= 0 || p > 65535 {
			return fmt.Errorf("invalid port %q", portSpec)
		}
		localPort = p
	}

	rawServer := *serverURL
	if rawServer == "" {
		rawServer = "http://127.0.0.1:8088"
	}
	if !strings.HasPrefix(rawServer, "http://") && !strings.HasPrefix(rawServer, "https://") {
		rawServer = "http://" + rawServer
	}
	parsedServer, err := url.Parse(rawServer)
	if err != nil {
		return fmt.Errorf("invalid server URL %q: %w", rawServer, err)
	}

	authToken := *token
	// If no token provided but username/password given, perform HTTP login.
	if authToken == "" && *username != "" && *password != "" {
		loginURL := fmt.Sprintf("%s/api/v1/auth/login", strings.TrimRight(rawServer, "/"))
		payload, _ := json.Marshal(map[string]string{"username": *username, "password": *password})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("creating login request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DuckJump-Request", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("login returned HTTP %d: %s", resp.StatusCode, string(body))
		}
		for _, c := range resp.Cookies() {
			if c.Name == "duckjump_session" {
				authToken = c.Value
				break
			}
		}
	}

	// If still no token but we have local database access, create a session directly.
	if authToken == "" && st != nil {
		var vlt *vault.Vault
		if masterKey := os.Getenv("DUCKJUMP_MASTER_KEY"); masterKey != "" {
			vlt, _ = vault.New(masterKey)
		}
		authSvc := &auth.Service{Store: st, Vault: vlt}
		var userID string
		if *username != "" {
			u, err := st.Q.GetUserByUsername(ctx, *username)
			if err == nil {
				userID = u.ID
			}
		}
		if userID == "" {
			// Find first admin or user
			users, err := st.Q.ListUsers(ctx)
			if err == nil && len(users) > 0 {
				userID = users[0].ID
			}
		}
		if userID != "" {
			tok, err := authSvc.NewSession(ctx, userID, false, "127.0.0.1", "duckjump forward cli")
			if err == nil {
				authToken = tok
			}
		}
	}

	listenAddr := fmt.Sprintf("%s:%d", *bind, localPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	defer listener.Close()

	wsScheme := "ws"
	if parsedServer.Scheme == "https" {
		wsScheme = "wss"
	}
	forwardEndpoint := fmt.Sprintf("%s://%s/api/v1/connections/%s/forward", wsScheme, parsedServer.Host, url.PathEscape(connName))
	if remotePort > 0 {
		forwardEndpoint += fmt.Sprintf("?port=%d", remotePort)
	}

	fmt.Printf(" duckJump Port Forwarding\n")
	fmt.Printf(" Listening on: %s\n", listenAddr)
	fmt.Printf(" Target conn:  %s", connName)
	if remotePort > 0 {
		fmt.Printf(" (port %d)", remotePort)
	}
	fmt.Printf("\n Gateway URL:  %s\n", rawServer)
	fmt.Printf(" Ready to accept connections. Press Ctrl+C to terminate.\n\n")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-sigCh
		fmt.Println("\nShutting down forwarder...")
		cancel()
		listener.Close()
	}()

	var activeConns atomic.Int64

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			continue
		}

		connNum := activeConns.Add(1)
		wg.Add(1)
		go func(c net.Conn, num int64) {
			defer wg.Done()
			defer activeConns.Add(-1)
			defer c.Close()

			remoteClient := c.RemoteAddr().String()
			nowStr := time.Now().Format("15:04:05")
			fmt.Printf("[%s] [#%d] Connection from %s -> dial gateway tunnel\n", nowStr, num, remoteClient)

			dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
			defer dialCancel()

			dialOpts := &websocket.DialOptions{
				HTTPHeader: make(http.Header),
			}
			if authToken != "" {
				dialOpts.HTTPHeader.Set("Authorization", "Bearer "+authToken)
				dialOpts.HTTPHeader.Set("Cookie", fmt.Sprintf("duckjump_session=%s", authToken))
			}

			ws, resp, err := websocket.Dial(dialCtx, forwardEndpoint, dialOpts)
			if err != nil {
				status := ""
				if resp != nil {
					status = fmt.Sprintf(" (HTTP %s)", resp.Status)
				}
				fmt.Fprintf(os.Stderr, "[%s] [#%d] Error connecting to gateway tunnel%s: %v\n", time.Now().Format("15:04:05"), num, status, err)
				return
			}
			defer ws.CloseNow()

			wsNetConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
			defer wsNetConn.Close()

			errCh := make(chan error, 2)
			var bytesSent, bytesRecv atomic.Int64

			go func() {
				n, err := io.Copy(wsNetConn, c)
				bytesSent.Store(n)
				errCh <- err
			}()

			go func() {
				n, err := io.Copy(c, wsNetConn)
				bytesRecv.Store(n)
				errCh <- err
			}()

			select {
			case <-ctx.Done():
			case <-errCh:
			}

			fmt.Printf("[%s] [#%d] Closed. Sent: %s, Received: %s\n",
				time.Now().Format("15:04:05"), num, formatBytes(bytesSent.Load()), formatBytes(bytesRecv.Load()))
		}(clientConn, connNum)
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
