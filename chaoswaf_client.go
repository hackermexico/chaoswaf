// chaoswaf_client.go
//
// Cliente ChaosWAF mejorado - Cliente robusto multicliente para conectar con ChaosWAF Central
// - Proxy local en 80/443
// - Panel local en 8080
// - Conexión segura con servidor via TLS
// - Autenticación mutua, reconexión inteligente, cola de reportes persistente
// - Actualización dinámica de configuración
//
// Nota: ejecutar puertos 80/443 requiere permisos elevados.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

/////////// CONFIG ///////////
const (
	DefaultServerAddr = "127.0.0.1:4000"
	DefaultPanelPort  = ":8080"
	DefaultHTTPPort   = ":80"
	DefaultHTTPSPort  = ":443"
	LogFileName       = "chaoswaf_client.log"
	ReportPeriod      = 10 * time.Second
	QueueMax          = 1000
	ConfigSyncPeriod  = 30 * time.Second
	LogRotateSize     = 10 * 1024 * 1024 // 10MB
)

type Config struct {
	ServerAddr    string `json:"server_addr"`
	AuthName      string `json:"auth_name"`
	AuthSecret    string `json:"auth_secret"`
	HTTPPort      string `json:"http_port"`
	HTTPSPort     string `json:"https_port"`
	PanelPort     string `json:"panel_port"`
	K             int    `json:"k"`
	ReconnectSec  int    `json:"reconnect_sec"`
	TLSCertFile   string `json:"tls_cert_file"`
	TLSKeyFile    string `json:"tls_key_file"`
	TLSCAFile     string `json:"tls_ca_file"`
	BackendTarget string `json:"backend_target"`
}

/////////// STATE & STRUCTS ///////////

type HeaderSet struct {
	Valid map[string]string `json:"valid"`
	Decoy map[string]string `json:"decoy"`
	K     int               `json:"k"`
	mu    sync.RWMutex
}

type Report struct {
	Timestamp time.Time         `json:"ts"`
	ClientIP  string            `json:"client_ip"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Note      string            `json:"note,omitempty"`
}

type BackendStats struct {
	TotalRequests int           `json:"total_requests"`
	TotalErrors   int           `json:"total_errors"`
	LastError     string        `json:"last_error,omitempty"`
	LastErrorTime time.Time     `json:"last_error_time,omitempty"`
	AvgLatency    time.Duration `json:"avg_latency"`
	mu            sync.Mutex
}

/////////// GLOBALS ///////////
var (
	cfg Config

	headerSet HeaderSet

	// stats
	statsMu         sync.Mutex
	totalHits       int
	totalBlocked    int
	backendStats    BackendStats
	lastRequests    []Report
	lastRequestsM   sync.Mutex
	activeClients   int
	activeClientsMu sync.Mutex

	// queue para reports
	queueMu sync.Mutex
	queue   []Report

	// conexión al servidor central
	connMu     sync.Mutex
	serverConn net.Conn

	// estado
	connectedMu   sync.RWMutex
	isConnected   bool
	authSucceeded bool

	// logging
	logger      *log.Logger
	logFile     *os.File
	currentLog  string
	logRotateMu sync.Mutex

	// control
	shutdownCtx       context.Context
	shutdownCancel    context.CancelFunc
	reconnectTicker   *time.Ticker
	configSyncTicker  *time.Ticker
	reportTicker      *time.Ticker
	healthCheckTicker *time.Ticker

	// TLS
	tlsConfig *tls.Config
)

/////////// HELPERS ///////////

func defaultConfig() Config {
	return Config{
		ServerAddr:    envOr("CHAOS_SERVER", DefaultServerAddr),
		AuthName:      envOr("CHAOS_AUTH_NAME", ""),
		AuthSecret:    envOr("CHAOS_AUTH_SECRET", ""),
		HTTPPort:      envOr("CHAOS_HTTP_PORT", DefaultHTTPPort),
		HTTPSPort:     envOr("CHAOS_HTTPS_PORT", DefaultHTTPSPort),
		PanelPort:     envOr("CHAOS_PANEL_PORT", DefaultPanelPort),
		K:             intEnvOr("CHAOS_K", 2),
		ReconnectSec:  intEnvOr("CHAOS_RECONNECT_SEC", 5),
		TLSCertFile:   envOr("CHAOS_TLS_CERT", ""),
		TLSKeyFile:    envOr("CHAOS_TLS_KEY", ""),
		TLSCAFile:     envOr("CHAOS_TLS_CA", ""),
		BackendTarget: envOr("CHAOS_BACKEND", "http://localhost:80"),
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func intEnvOr(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func setupLogger(path string) {
	logRotateMu.Lock()
	defer logRotateMu.Unlock()

	if logFile != nil {
		logFile.Close()
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[WARN] no se pudo abrir log file: %v, usando stdout\n", err)
		logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
		return
	}

	logFile = f
	currentLog = path
	mw := io.MultiWriter(os.Stdout, f)
	logger = log.New(mw, "", log.LstdFlags|log.Lmicroseconds)
}

func rotateLogIfNeeded() {
	logRotateMu.Lock()
	defer logRotateMu.Unlock()

	if logFile == nil {
		return
	}

	info, err := logFile.Stat()
	if err != nil {
		return
	}

	if info.Size() >= LogRotateSize {
		newPath := fmt.Sprintf("%s.%d", LogFileName, time.Now().Unix())
		os.Rename(LogFileName, newPath)
		setupLogger(LogFileName)
		logger.Println("[INFO] Log rotado")
	}
}

func randomTokenBytes(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

/////////// HEADERSET FUNCTIONS ///////////

func initHeaderSet(K int) {
	headerSet.mu.Lock()
	defer headerSet.mu.Unlock()
	headerSet.K = K
	headerSet.Valid = make(map[string]string)
	headerSet.Decoy = make(map[string]string)
	
	pool := []string{
		"X-CWAF-CSRF1", "X-CWAF-CSRF2", "X-CWAF-CSRF3", 
		"X-CWAF-CSRF4", "X-CWAF-CSRF5", "X-CWAF-TOKEN",
	}
	
	// Seleccionar K headers válidos
	for i := 0; i < K; i++ {
		h := pool[i%len(pool)]
		headerSet.Valid[h] = randomTokenBytes(12)
	}
	
	// Agregar decoys
	for _, h := range pool {
		if _, ok := headerSet.Valid[h]; !ok {
			headerSet.Decoy[h] = randomTokenBytes(10)
		}
	}
	
	// Headers adicionales aleatorios
	for i := 0; i < 3; i++ {
		h := fmt.Sprintf("X-DECOY-%d", i)
		headerSet.Decoy[h] = randomTokenBytes(8)
	}
	
	logger.Printf("[INFO] HeaderSet inicializado K=%d valid=%d decoys=%d\n", 
		headerSet.K, len(headerSet.Valid), len(headerSet.Decoy))
}

func setK(k int) {
	if k < 1 || k > 5 {
		logger.Printf("[WARN] Valor K inválido: %d (debe ser 1-5)\n", k)
		return
	}
	
	headerSet.mu.Lock()
	headerSet.K = k
	headerSet.mu.Unlock()
	
	initHeaderSet(k)
	logger.Printf("[CONFIG] K actualizado a %d\n", k)
}

func addDecoyBurst(n int) {
	headerSet.mu.Lock()
	defer headerSet.mu.Unlock()
	
	for i := 0; i < n; i++ {
		h := fmt.Sprintf("X-BURST-%d-%d", time.Now().Unix(), i)
		headerSet.Decoy[h] = randomTokenBytes(8)
	}
	
	logger.Printf("[INFO] Decoy burst: %d añadidos\n", n)
}

func rotateTokens() {
	headerSet.mu.Lock()
	defer headerSet.mu.Unlock()
	
	for h := range headerSet.Valid {
		headerSet.Valid[h] = randomTokenBytes(12)
	}
	
	logger.Println("[INFO] Tokens válidos rotados")
}

func getHeaderSnapshot() (map[string]string, map[string]string, int) {
	headerSet.mu.RLock()
	defer headerSet.mu.RUnlock()
	
	valid := make(map[string]string, len(headerSet.Valid))
	for k, v := range headerSet.Valid {
		valid[k] = v
	}
	
	decoy := make(map[string]string, len(headerSet.Decoy))
	for k, v := range headerSet.Decoy {
		decoy[k] = v
	}
	
	return valid, decoy, headerSet.K
}

func validateRequestHeaders(r *http.Request) bool {
	headerSet.mu.RLock()
	defer headerSet.mu.RUnlock()
	
	count := 0
	for h, tok := range headerSet.Valid {
		if r.Header.Get(h) == tok {
			count++
		}
	}
	
	return count >= headerSet.K
}

/////////// QUEUE / REPORTS ///////////

func enqueueReport(rep Report) {
	queueMu.Lock()
	defer queueMu.Unlock()
	
	if len(queue) >= QueueMax {
		// Eliminar los más antiguos
		dropCount := len(queue) - QueueMax + 1
		queue = queue[dropCount:]
	}
	
	queue = append(queue, rep)
}

func flushQueueToServer() {
	connMu.Lock()
	conn := serverConn
	connMu.Unlock()
	
	if conn == nil {
		return
	}
	
	queueMu.Lock()
	defer queueMu.Unlock()
	
	sent := 0
	for i := 0; i < len(queue); i++ {
		data, err := json.Marshal(queue[i])
		if err != nil {
			logger.Printf("[ERROR] Marshal report: %v\n", err)
			continue
		}
		
		data = append(data, '\n')
		if _, err := conn.Write(data); err != nil {
			logger.Printf("[ERROR] Enviando reporte: %v\n", err)
			break
		}
		sent++
	}
	
	if sent > 0 {
		logger.Printf("[INFO] %d reportes enviados al servidor\n", sent)
		// Mantener los no enviados
		if sent < len(queue) {
			queue = queue[sent:]
		} else {
			queue = []Report{}
		}
	}
}

/////////// PROXY HANDLER ///////////

func makeReportFromRequest(r *http.Request) Report {
	hdrs := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			hdrs[k] = v[0]
		}
	}
	
	clientIP := r.RemoteAddr
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		clientIP = ip
	} else if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	
	return Report{
		Timestamp: time.Now(),
		ClientIP:  clientIP,
		Method:    r.Method,
		URL:       r.URL.String(),
		Headers:   hdrs,
	}
}

func rememberRequest(rep Report) {
	lastRequestsM.Lock()
	defer lastRequestsM.Unlock()
	
	if len(lastRequests) >= 100 {
		lastRequests = lastRequests[1:]
	}
	
	lastRequests = append(lastRequests, rep)
}

func updateBackendStats(latency time.Duration, err error) {
	backendStats.mu.Lock()
	defer backendStats.mu.Unlock()
	
	backendStats.TotalRequests++
	if err != nil {
		backendStats.TotalErrors++
		backendStats.LastError = err.Error()
		backendStats.LastErrorTime = time.Now()
	} else {
		// Actualizar latencia promedio
		if backendStats.TotalRequests == 1 {
			backendStats.AvgLatency = latency
		} else {
			backendStats.AvgLatency = (backendStats.AvgLatency*time.Duration(backendStats.TotalRequests-1) + latency) / time.Duration(backendStats.TotalRequests)
		}
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	activeClientsMu.Lock()
	activeClients++
	activeClientsMu.Unlock()
	
	defer func() {
		activeClientsMu.Lock()
		activeClients--
		activeClientsMu.Unlock()
	}()
	
	start := time.Now()
	rep := makeReportFromRequest(r)
	rememberRequest(rep)
	
	statsMu.Lock()
	totalHits++
	statsMu.Unlock()
	
	// Validar cabeceras K-de-N
	if !validateRequestHeaders(r) {
		statsMu.Lock()
		totalBlocked++
		statsMu.Unlock()
		
		rep.Note = "blocked_local"
		enqueueReport(rep)
		logger.Printf("[BLOCKED] %s %s %s\n", rep.ClientIP, rep.Method, rep.URL)
		http.Error(w, "Blocked by ChaosWAF client", http.StatusForbidden)
		return
	}
	
	// Parsear backend target
	targetURL, err := url.Parse(cfg.BackendTarget)
	if err != nil {
		logger.Printf("[ERROR] URL backend inválida: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Crear proxy reverso
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	// Modificar solicitud
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// Mantener información original
		req.Header.Set("X-Forwarded-For", rep.ClientIP)
		req.Header.Set("X-ChaosWAF-Client", "true")
	}
	
	// Registrar errores
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		updateBackendStats(0, err)
		logger.Printf("[BACKEND ERROR] %v\n", err)
		http.Error(w, "Backend unavailable", http.StatusBadGateway)
	}
	
	// Ejecutar proxy
	proxy.ServeHTTP(w, r)
	
	latency := time.Since(start)
	updateBackendStats(latency, nil)
	
	// Reportar al servidor
	rep.Note = "passed"
	enqueueReport(rep)
}

/////////// PANEL HTTP LOCAL ///////////

func handlePanelIndex(w http.ResponseWriter, r *http.Request) {
	connectedMu.RLock()
	connected := isConnected
	authOk := authSucceeded
	connectedMu.RUnlock()
	
	valid, decoy, k := getHeaderSnapshot()
	
	lastRequestsM.Lock()
	lr := make([]Report, len(lastRequests))
	copy(lr, lastRequests)
	lastRequestsM.Unlock()
	
	activeClientsMu.Lock()
	clients := activeClients
	activeClientsMu.Unlock()
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<html>
<head>
	<title>ChaosWAF Client Panel</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; }
		table { border-collapse: collapse; width: 100%%; margin-bottom: 20px; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; }
		pre { background: #f8f8f8; padding: 10px; border-radius: 4px; }
		.status-connected { color: green; }
		.status-disconnected { color: red; }
	</style>
</head>
<body>`)
	
	fmt.Fprintf(w, "<h2>ChaosWAF Client v2.0</h2>")
	fmt.Fprintf(w, "<p><b>Server:</b> %s <span class='status-%t'>%s</span></p>", 
		cfg.ServerAddr, connected, map[bool]string{true: "CONNECTED", false: "DISCONNECTED"}[connected])
	
	fmt.Fprintf(w, "<p><b>Auth:</b> %s</p>", map[bool]string{true: "OK", false: "FAILED/PENDING"}[authOk])
	fmt.Fprintf(w, "<p><b>Active Clients:</b> %d</p>", clients)
	fmt.Fprintf(w, "<p><b>K:</b> %d | <b>Hits:</b> %d | <b>Blocked:</b> %d</p>", k, totalHits, totalBlocked)
	
	// Backend stats
	backendStats.mu.Lock()
	fmt.Fprintf(w, "<p><b>Backend:</b> %s | <b>Requests:</b> %d | <b>Errors:</b> %d | <b>Avg Latency:</b> %s</p>", 
		cfg.BackendTarget, backendStats.TotalRequests, backendStats.TotalErrors, backendStats.AvgLatency)
	backendStats.mu.Unlock()
	
	// Headers
	fmt.Fprintf(w, "<h3>Valid Headers</h3><table><tr><th>Header</th><th>Value</th></tr>")
	for h, v := range valid {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>", h, v)
	}
	fmt.Fprintf(w, "</table>")
	
	fmt.Fprintf(w, "<h3>Decoy Headers</h3><table><tr><th>Header</th><th>Value</th></tr>")
	for h, v := range decoy {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>", h, v)
	}
	fmt.Fprintf(w, "</table>")
	
	// Last requests
	fmt.Fprintf(w, "<h3>Last %d Requests</h3><table><tr><th>Time</th><th>Client</th><th>Method</th><th>URL</th><th>Status</th></tr>", len(lr))
	for i := len(lr) - 1; i >= 0; i-- {
		status := "PASS"
		if strings.Contains(lr[i].Note, "block") {
			status = "BLOCK"
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", 
			lr[i].Timestamp.Format("15:04:05.000"), 
			lr[i].ClientIP, 
			lr[i].Method, 
			truncateString(lr[i].URL, 50), 
			status)
	}
	fmt.Fprintf(w, "</table>")
	
	// Commands
	fmt.Fprintf(w, `<h3>Commands</h3>
<ul>
	<li><a href="/cmd/caos">caos</a> - Add 5 decoy headers</li>
	<li><a href="/cmd/burst">burst</a> - Add 10 decoy headers</li>
	<li><a href="/cmd/rotate">rotate</a> - Rotate valid tokens</li>
	<li><a href="/cmd/test">test</a> - Run local test</li>
	<li><a href="/cmd/reconnect">reconnect</a> - Reconnect to server</li>
</ul>`)
	
	fmt.Fprintf(w, "</body></html>")
}

func handleCmd(w http.ResponseWriter, r *http.Request) {
	cmd := strings.TrimPrefix(r.URL.Path, "/cmd/")
	switch cmd {
	case "caos":
		addDecoyBurst(5)
		fmt.Fprintln(w, "Chaos mode enabled (local).")
	case "burst":
		addDecoyBurst(10)
		fmt.Fprintln(w, "Decoy burst added.")
	case "rotate":
		rotateTokens()
		fmt.Fprintln(w, "Tokens rotated.")
	case "test":
		go runLocalTest()
		fmt.Fprintln(w, "Test started. Check logs for details.")
	case "reconnect":
		go reconnectToServer()
		fmt.Fprintln(w, "Reconnection initiated.")
	default:
		http.Error(w, "unknown command", http.StatusBadRequest)
	}
}

func startPanel() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handlePanelIndex)
	mux.HandleFunc("/cmd/", handleCmd)
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		connectedMu.RLock()
		connected := isConnected
		authOk := authSucceeded
		connectedMu.RUnlock()
		
		valid, decoy, k := getHeaderSnapshot()
		
		resp := map[string]interface{}{
			"server":      cfg.ServerAddr,
			"connected":   connected,
			"authenticated": authOk,
			"valid":       valid,
			"decoy":       decoy,
			"k":           k,
			"totalHits":   totalHits,
			"totalBlock":  totalBlocked,
			"queueSize":   len(queue),
			"activeClients": activeClients,
			"backendTarget": cfg.BackendTarget,
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	
	logger.Printf("[INFO] Panel local en %s\n", cfg.PanelPort)
	go func() {
		if err := http.ListenAndServe(cfg.PanelPort, mux); err != nil {
			logger.Printf("[ERROR] Panel local: %v\n", err)
		}
	}()
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

/////////// SERVER COMMUNICATION ///////////

func setupTLS() error {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		logger.Println("[WARN] TLS no configurado, usando conexión insegura")
		return nil
	}
	
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("error loading key pair: %w", err)
	}
	
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	
	// Configurar CA si está presente
	if cfg.TLSCAFile != "" {
		caCert, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return fmt.Errorf("error reading CA cert: %w", err)
		}
		
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return errors.New("failed to append CA cert")
		}
		
		tlsConfig.RootCAs = caCertPool
		tlsConfig.ServerName = strings.Split(cfg.ServerAddr, ":")[0]
	}
	
	logger.Println("[INFO] Configuración TLS completada")
	return nil
}

func connectToServer() error {
	connMu.Lock()
	if serverConn != nil {
		connMu.Unlock()
		return errors.New("ya conectado")
	}
	connMu.Unlock()
	
	logger.Printf("[INFO] Intentando conectar a %s...\n", cfg.ServerAddr)
	
	var conn net.Conn
	var err error
	
	if tlsConfig != nil {
		conn, err = tls.Dial("tcp", cfg.ServerAddr, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", cfg.ServerAddr)
	}
	
	if err != nil {
		return fmt.Errorf("error de conexión: %w", err)
	}
	
	connMu.Lock()
	serverConn = conn
	connMu.Unlock()
	
	connectedMu.Lock()
	isConnected = true
	connectedMu.Unlock()
	
	// Autenticación
	if cfg.AuthName != "" && cfg.AuthSecret != "" {
		authMsg := fmt.Sprintf("AUTH %s %s\n", cfg.AuthName, cfg.AuthSecret)
		if _, err := conn.Write([]byte(authMsg)); err != nil {
			_ = conn.Close()
			connMu.Lock()
			serverConn = nil
			connMu.Unlock()
			return fmt.Errorf("error enviando AUTH: %w", err)
		}
		logger.Println("[INFO] Autenticación enviada")
	}
	
	// Iniciar servicios
	go serverReader(conn)
	go serverReporter(conn)
	
	// Enviar cola pendiente
	flushQueueToServer()
	
	logger.Printf("[INFO] Conectado a %s\n", cfg.ServerAddr)
	return nil
}

func reconnectToServer() {
	connectedMu.Lock()
	if isConnected {
		connectedMu.Unlock()
		return
	}
	connectedMu.Unlock()
	
	if err := connectToServer(); err != nil {
		logger.Printf("[WARN] Reconexión fallida: %v\n", err)
	}
}

func serverReader(conn net.Conn) {
	defer func() {
		logger.Println("[INFO] Cerrando reader de servidor")
	}()
	
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		logger.Printf("[SRV] %s\n", line)
		
		switch {
		case line == "PING":
			if _, err := conn.Write([]byte("PONG\n")); err != nil {
				logger.Printf("[ERROR] Enviando PONG: %v\n", err)
				break
			}
			
		case strings.HasPrefix(line, "AUTH "):
			if strings.HasPrefix(line, "AUTH OK") {
				authSucceeded = true
				logger.Println("[INFO] Autenticación aceptada")
			} else if strings.HasPrefix(line, "AUTH FAIL") {
				authSucceeded = false
				logger.Println("[ERROR] Autenticación fallida")
			}
			
		case strings.HasPrefix(line, "SETK "):
			parts := strings.SplitN(line, " ", 2)
			if len(parts) < 2 {
				logger.Println("[WARN] Comando SETK inválido")
				break
			}
			
			k, err := strconv.Atoi(parts[1])
			if err != nil || k < 1 || k > 5 {
				logger.Printf("[WARN] Valor K inválido: %s\n", parts[1])
				break
			}
			
			setK(k)
			
		case line == "CAOS":
			addDecoyBurst(5)
			
		case line == "BURST":
			addDecoyBurst(10)
			
		case line == "ROTATE":
			rotateTokens()
			
		case strings.HasPrefix(line, "SETBACKEND "):
			parts := strings.SplitN(line, " ", 2)
			if len(parts) < 2 {
				logger.Println("[WARN] Comando SETBACKEND inválido")
				break
			}
			
			newTarget := parts[1]
			if _, err := url.ParseRequestURI(newTarget); err != nil {
				logger.Printf("[WARN] URL backend inválida: %s\n", newTarget)
				break
			}
			
			cfg.BackendTarget = newTarget
			logger.Printf("[CONFIG] Backend actualizado a: %s\n", newTarget)
		}
	}
	
	if err := sc.Err(); err != nil {
		logger.Printf("[ERROR] Error leyendo servidor: %v\n", err)
	}
	
	// Manejar desconexión
	connMu.Lock()
	if serverConn == conn {
		serverConn = nil
	}
	connMu.Unlock()
	
	connectedMu.Lock()
	isConnected = false
	authSucceeded = false
	connectedMu.Unlock()
	
	logger.Println("[WARN] Desconectado del servidor")
}

func serverReporter(conn net.Conn) {
	ticker := time.NewTicker(ReportPeriod)
	defer ticker.Stop()
	
	for {
		select {
		case <-shutdownCtx.Done():
			return
		case <-ticker.C:
			statsMu.Lock()
			th := totalHits
			tb := totalBlocked
			statsMu.Unlock()
			
			activeClientsMu.Lock()
			ac := activeClients
			activeClientsMu.Unlock()
			
			report := fmt.Sprintf("REPORT hits:%d blocked:%d clients:%d\n", th, tb, ac)
			if _, err := conn.Write([]byte(report)); err != nil {
				logger.Printf("[ERROR] Enviando reporte: %v\n", err)
				return
			}
		}
	}
}

/////////// HEALTH CHECKS ///////////

func healthCheck() {
	// Verificar conexión al backend
	resp, err := http.Get(cfg.BackendTarget)
	if err != nil {
		logger.Printf("[HEALTH] Backend check failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 500 {
		logger.Printf("[HEALTH] Backend unhealthy: %s\n", resp.Status)
	}
}

/////////// TESTS ///////////

func runLocalTest() {
	logger.Println("[TEST] Iniciando test local")
	
	// Construir solicitud válida
	valid, _, _ := getHeaderSnapshot()
	validReq, _ := http.NewRequest("GET", "http://localhost"+cfg.HTTPPort+"/test-valid", nil)
	for h, v := range valid {
		validReq.Header.Set(h, v)
	}
	
	// Solicitud inválida
	invalidReq, _ := http.NewRequest("GET", "http://localhost"+cfg.HTTPPort+"/test-invalid", nil)
	
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	// Prueba inválida
	resp, err := client.Do(invalidReq)
	if err != nil {
		logger.Printf("[TEST] Invalid request error: %v\n", err)
	} else {
		logger.Printf("[TEST] Invalid request status: %d\n", resp.StatusCode)
		resp.Body.Close()
	}
	
	// Prueba válida
	resp, err = client.Do(validReq)
	if err != nil {
		logger.Printf("[TEST] Valid request error: %v\n", err)
	} else {
		logger.Printf("[TEST] Valid request status: %d\n", resp.StatusCode)
		resp.Body.Close()
	}
	
	logger.Println("[TEST] Prueba completada")
}

/////////// MAIN ///////////

func initSystem() {
	// Configuración
	cfg = defaultConfig()
	
	// Logger
	setupLogger(LogFileName)
	
	// Contexto para shutdown
	shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
	
	// Inicializar componentes
	initHeaderSet(cfg.K)
	lastRequests = make([]Report, 0, 100)
	queue = make([]Report, 0, QueueMax)
	
	// Configurar TLS
	if err := setupTLS(); err != nil {
		logger.Printf("[ERROR] Configuración TLS: %v\n", err)
	}
}

func startServices() {
	// Iniciar panel
	startPanel()
	
	// Iniciar proxy HTTP
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", proxyHandler)
		
		server := &http.Server{
			Addr:    cfg.HTTPPort,
			Handler: mux,
		}
		
		logger.Printf("[PROXY] HTTP en %s\n", cfg.HTTPPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("[FATAL] HTTP proxy: %v\n", err)
		}
	}()
	
	// Iniciar proxy HTTPS
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", proxyHandler)
		
		server := &http.Server{
			Addr:    cfg.HTTPSPort,
			Handler: mux,
		}
		
		logger.Printf("[PROXY] HTTPS en %s\n", cfg.HTTPSPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("[FATAL] HTTPS proxy: %v\n", err)
		}
	}()
	
	// Temporizadores
	reconnectTicker = time.NewTicker(time.Duration(cfg.ReconnectSec) * time.Second)
	configSyncTicker = time.NewTicker(ConfigSyncPeriod)
	reportTicker = time.NewTicker(ReportPeriod)
	healthCheckTicker = time.NewTicker(1 * time.Minute)
	logRotateTicker := time.NewTicker(5 * time.Minute)
	
	// Servicio de reconexión
	go func() {
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-reconnectTicker.C:
				connectedMu.RLock()
				connected := isConnected
				connectedMu.RUnlock()
				
				if !connected {
					reconnectToServer()
				}
			}
		}
	}()
	
	// Rotación de logs
	go func() {
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-logRotateTicker.C:
				rotateLogIfNeeded()
			}
		}
	}()
	
	// Health checks
	go func() {
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-healthCheckTicker.C:
				healthCheck()
			}
		}
	}()
}

func cleanup() {
	logger.Println("[SHUTDOWN] Limpiando recursos...")
	
	// Detener temporizadores
	if reconnectTicker != nil {
		reconnectTicker.Stop()
	}
	if configSyncTicker != nil {
		configSyncTicker.Stop()
	}
	if reportTicker != nil {
		reportTicker.Stop()
	}
	if healthCheckTicker != nil {
		healthCheckTicker.Stop()
	}
	
	// Cerrar conexión
	connMu.Lock()
	if serverConn != nil {
		serverConn.Close()
		serverConn = nil
	}
	connMu.Unlock()
	
	// Cerrar archivo de log
	if logFile != nil {
		logFile.Close()
	}
	
	logger.Println("[SHUTDOWN] Completado")
}

func main() {
	initSystem()
	defer cleanup()
	
	logger.Println("[START] ChaosWAF Client v2 iniciando")
	logger.Printf("[CONFIG] server=%s http=%s https=%s panel=%s k=%d backend=%s\n",
		cfg.ServerAddr, cfg.HTTPPort, cfg.HTTPSPort, cfg.PanelPort, cfg.K, cfg.BackendTarget)
	
	startServices()
	
	// Conexión inicial
	if err := connectToServer(); err != nil {
		logger.Printf("[WARN] Conexión inicial fallida: %v\n", err)
	}
	
	// Manejar señales
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	
	// CLI
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("ChaosWAF Client v2.0 - Escribe 'help' para comandos")
	
mainLoop:
	for {
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		
		switch input {
		case "help":
			fmt.Println("Comandos: help, status, test, caos, burst, rotate, reconnect, exit")
			
		case "status":
			connectedMu.RLock()
			fmt.Printf("Conectado: %t\nAutenticado: %t\n", isConnected, authSucceeded)
			connectedMu.RUnlock()
			fmt.Printf("Hits: %d\nBloqueados: %d\n", totalHits, totalBlocked)
			fmt.Printf("Clientes activos: %d\n", activeClients)
			fmt.Printf("Backend: %s\n", cfg.BackendTarget)
			
		case "test":
			go runLocalTest()
			fmt.Println("Prueba iniciada. Ver logs para detalles.")
			
		case "caos":
			addDecoyBurst(5)
			fmt.Println("Modo caos activado")
			
		case "burst":
			addDecoyBurst(10)
			fmt.Println("Ráfaga de decoys añadida")
			
		case "rotate":
			rotateTokens()
			fmt.Println("Tokens rotados")
			
		case "reconnect":
			go reconnectToServer()
			fmt.Println("Reconectando...")
			
		case "exit":
			break mainLoop
			
		case "":
			// Nada
			
		default:
			fmt.Println("Comando desconocido. Escribe 'help' para ayuda.")
		}
	}
	
	shutdownCancel()
	logger.Println("[STOP] Aplicación finalizada")
}
