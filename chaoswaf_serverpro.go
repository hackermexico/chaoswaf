package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultListen    = ":4000"
	defaultPanel     = ":8081"
	logFileName      = "server_chaoswaf.log"
	eventsMax        = 5000
	pingInterval     = 30 * time.Second
	pongTimeout      = 20 * time.Second
	clientHistoryMax = 100
	csrfTokenLength  = 32
)

type Client struct {
	ID           string      `json:"id"`
	Remote       string      `json:"remote"`
	Authed       bool        `json:"authed"`
	TokenName    string      `json:"token_name,omitempty"`
	Conn         net.Conn    `json:"-"`
	LastReport   string      `json:"last_report"`
	LastSeen     time.Time   `json:"last_seen"`
	ConnectedAt  time.Time   `json:"connected_at"`
	Health       string      `json:"health"`
	PendingPong  bool        `json:"pending_pong"`
	Tags         []string    `json:"tags,omitempty"`
	Country      string      `json:"country,omitempty"`
	History      []string    `json:"-"`
	mu           sync.Mutex  `json:"-"`
}

type Event struct {
	TS      time.Time `json:"ts"`
	Level   string    `json:"level"`
	Client  string    `json:"client,omitempty"`
	Message string    `json:"message"`
}

type Stats struct {
	sync.Mutex
	TotalConnections int `json:"total_connections"`
	CurrentClients   int `json:"current_clients"`
	AuthAccepted     int `json:"auth_accepted"`
	AuthRejected     int `json:"auth_rejected"`
	Kicked           int `json:"kicked"`
	TimeOuts         int `json:"timeouts"`
	CommandsExecuted int `json:"commands_executed"`
}

type Config struct {
	ListenAddr      string
	PanelAddr       string
	AuthTokens      map[string]string
	TLSCert         string
	TLSKey          string
	EnableTLS       bool
	RateLimit       int
	Whitelist       []string
	PanelUsername   string
	PanelPassword   string
	PersistInterval time.Duration
	SecretKey       string
}

var (
	clients   = make(map[string]*Client)
	muClients sync.RWMutex
	events    []Event
	muEvents  sync.RWMutex
	stats     Stats
	config    Config
	logWriter io.Writer
	stopChan  = make(chan struct{})
	csrfStore = make(map[string]time.Time)
	muCSRF    sync.Mutex
)

func init() {
	config = loadConfig()
	
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for {
			select {
			case <-ticker.C:
				cleanupCSRFTokens()
			case <-stopChan:
				return
			}
		}
	}()
}

func loadConfig() Config {
	secretKey := getenv("CHAOS_SECRET_KEY", "")
	if secretKey == "" {
		secretKey = generateRandomString(64)
	}

	return Config{
		ListenAddr:      getenv("CHAOS_LISTEN", defaultListen),
		PanelAddr:       getenv("CHAOS_PANEL", defaultPanel),
		AuthTokens:      parseTokens(getenv("CHAOS_AUTH_TOKENS", "")),
		TLSCert:         getenv("CHAOS_TLS_CERT", ""),
		TLSKey:          getenv("CHAOS_TLS_KEY", ""),
		EnableTLS:       getenv("CHAOS_ENABLE_TLS", "false") == "true",
		RateLimit:       atoi(getenv("CHAOS_RATE_LIMIT", "10")),
		Whitelist:       splitAndTrim(getenv("CHAOS_WHITELIST", ""), ","),
		PanelUsername:   getenv("CHAOS_PANEL_USER", ""),
		PanelPassword:   getenv("CHAOS_PANEL_PASS", ""),
		PersistInterval: time.Duration(atoi(getenv("CHAOS_PERSIST_INTERVAL", "300"))) * time.Second,
		SecretKey:       secretKey,
	}
}

// *************** SEGURIDAD Y ANTI-CSRF ***************
func generateCSRFToken() string {
	b := make([]byte, csrfTokenLength)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Error generando token CSRF: %v", err)
		return ""
	}
	token := base64.URLEncoding.EncodeToString(b)
	muCSRF.Lock()
	csrfStore[token] = time.Now().Add(30 * time.Minute)
	muCSRF.Unlock()
	return token
}

func validateCSRFToken(token string) bool {
	muCSRF.Lock()
	defer muCSRF.Unlock()
	
	if expiry, exists := csrfStore[token]; exists {
		if time.Now().Before(expiry) {
			delete(csrfStore, token)
			return true
		}
	}
	return false
}

func cleanupCSRFTokens() {
	muCSRF.Lock()
	defer muCSRF.Unlock()
	
	now := time.Now()
	for token, expiry := range csrfStore {
		if now.After(expiry) {
			delete(csrfStore, token)
		}
	}
}

// *************** UTILIDADES ***************
func getenv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func atoi(s string) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return 0
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func parseTokens(raw string) map[string]string {
	tokens := make(map[string]string)
	if raw == "" {
		return tokens
	}
	
	pairs := strings.Split(raw, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" && value != "" {
			tokens[key] = value
		}
	}
	return tokens
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Error generando cadena aleatoria: %v", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}

func setupLogging() {
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("[WARN] Error al abrir archivo de log:", err)
		logWriter = os.Stdout
	} else {
		logWriter = io.MultiWriter(os.Stdout, logFile)
	}
	log.SetOutput(logWriter)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}

func addEvent(level, clientID, message string) {
	event := Event{
		TS:      time.Now(),
		Level:   level,
		Client:  clientID,
		Message: message,
	}
	
	muEvents.Lock()
	defer muEvents.Unlock()
	
	events = append(events, event)
	if len(events) > eventsMax {
		keep := eventsMax / 2
		events = events[len(events)-keep:]
	}
	
	log.Printf("[%s][%s] %s", level, clientID, message)
}

// *************** GESTIÓN DE CLIENTES ***************
func registerClient(conn net.Conn) *Client {
	remoteAddr := conn.RemoteAddr().String()
	client := &Client{
		ID:          remoteAddr,
		Remote:      remoteAddr,
		Authed:      false,
		Conn:        conn,
		LastSeen:    time.Now(),
		ConnectedAt: time.Now(),
		Health:      "unverified",
		History:     make([]string, 0, clientHistoryMax),
	}
	
	muClients.Lock()
	defer muClients.Unlock()
	
	clients[remoteAddr] = client
	stats.Lock()
	stats.TotalConnections++
	stats.CurrentClients = len(clients)
	stats.Unlock()
	
	addEvent("INFO", client.ID, "Cliente conectado")
	return client
}

func unregisterClient(client *Client, reason string) {
	muClients.Lock()
	delete(clients, client.ID)
	stats.Lock()
	stats.CurrentClients = len(clients)
	stats.Unlock()
	muClients.Unlock()
	
	client.Conn.Close()
	addEvent("INFO", client.ID, "Cliente desconectado: "+reason)
}

func tryAuth(line string, client *Client) bool {
	if !strings.HasPrefix(line, "AUTH ") {
		addEvent("WARN", client.ID, "Cliente legacy sin autenticación")
		return true
	}
	
	parts := strings.Fields(line)
	if len(parts) < 3 {
		addEvent("ERROR", client.ID, "Formato AUTH inválido")
		return false
	}
	
	tokenName := parts[1]
	tokenSecret := parts[2]
	
	if storedSecret, exists := config.AuthTokens[tokenName]; exists && storedSecret == tokenSecret {
		client.mu.Lock()
		client.Authed = true
		client.TokenName = tokenName
		
		if len(parts) >= 4 {
			tags := strings.Split(parts[3], ",")
			for _, tag := range tags {
				if trimmed := strings.TrimSpace(tag); trimmed != "" {
					client.Tags = append(client.Tags, trimmed)
				}
			}
		}
		client.mu.Unlock()
		
		stats.Lock()
		stats.AuthAccepted++
		stats.Unlock()
		
		addEvent("INFO", client.ID, "Autenticación exitosa con token: "+tokenName)
		return true
	}
	
	stats.Lock()
	stats.AuthRejected++
	stats.Unlock()
	
	addEvent("ERROR", client.ID, "Autenticación fallida con token: "+tokenName)
	return false
}

func isWhitelisted(ip string) bool {
	if len(config.Whitelist) == 0 {
		return true
	}
	
	for _, allowed := range config.Whitelist {
		if allowed == ip {
			return true
		}
		if _, ipnet, err := net.ParseCIDR(allowed); err == nil {
			if addr := net.ParseIP(ip); addr != nil && ipnet.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// *************** TÉCNICAS DE DISPERSIÓN ***************
func disperseCommand(command string, percentage int) int {
	muClients.RLock()
	defer muClients.RUnlock()
	
	if percentage <= 0 || percentage > 100 {
		percentage = 100
	}

	total := len(clients)
	if total == 0 {
		return 0
	}

	targetCount := total * percentage / 100
	if targetCount == 0 {
		targetCount = 1
	}

	count := 0
	for _, client := range clients {
		if count >= targetCount {
			break
		}
		
		client.mu.Lock()
		if _, err := client.Conn.Write([]byte(command + "\n")); err == nil {
			count++
		}
		client.mu.Unlock()
	}
	
	addEvent("INFO", "", fmt.Sprintf("Comando dispersado: '%s' a %d/%d clientes (%d%%)", 
		command, count, total, percentage))
	return count
}

// *************** MANEJADORES DE CONEXIONES ***************
func handleClient(conn net.Conn) {
	clientIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
	
	if !isWhitelisted(clientIP) {
		addEvent("WARN", conn.RemoteAddr().String(), "Intento de conexión no permitido desde: "+clientIP)
		conn.Close()
		return
	}
	
	client := registerClient(conn)
	defer unregisterClient(client, "Conexión cerrada")
	
	rateLimiter := time.NewTicker(time.Second / time.Duration(config.RateLimit))
	defer rateLimiter.Stop()
	
	stopPing := make(chan struct{})
	go func() {
		pingTicker := time.NewTicker(pingInterval)
		defer pingTicker.Stop()
		
		for {
			select {
			case <-pingTicker.C:
				client.mu.Lock()
				client.PendingPong = true
				client.mu.Unlock()
				
				if _, err := client.Conn.Write([]byte("PING\n")); err != nil {
					return
				}
				
				go func(c *Client) {
					time.Sleep(pongTimeout)
					c.mu.Lock()
					defer c.mu.Unlock()
					
					if c.PendingPong {
						c.Health = "timeout"
						stats.Lock()
						stats.TimeOuts++
						stats.Unlock()
						addEvent("WARN", c.ID, "Timeout de PONG")
					}
				}(client)
				
			case <-stopPing:
				return
			}
		}
	}()
	
	scanner := bufio.NewScanner(conn)
	firstLine := true
	
	for scanner.Scan() {
		<-rateLimiter.C
		
		line := strings.TrimSpace(scanner.Text())
		client.mu.Lock()
		client.LastSeen = time.Now()
		
		if len(client.History) >= clientHistoryMax {
			client.History = client.History[1:]
		}
		client.History = append(client.History, line)
		client.mu.Unlock()
		
		if firstLine {
			firstLine = false
			if !tryAuth(line, client) {
				client.Conn.Write([]byte("ERR AUTH\n"))
				return
			}
			client.Conn.Write([]byte("OK AUTH\n"))
			continue
		}
		
		switch {
		case line == "PONG":
			client.mu.Lock()
			client.PendingPong = false
			client.Health = "healthy"
			client.mu.Unlock()
			addEvent("DEBUG", client.ID, "PONG recibido")
			
		case strings.HasPrefix(line, "REPORT "):
			report := strings.TrimPrefix(line, "REPORT ")
			client.mu.Lock()
			client.LastReport = report
			client.mu.Unlock()
			addEvent("REPORT", client.ID, report)
			
		case strings.HasPrefix(line, "CMD "):
			cmd := strings.TrimPrefix(line, "CMD ")
			addEvent("COMMAND", client.ID, "Comando ejecutado: "+cmd)
			stats.Lock()
			stats.CommandsExecuted++
			stats.Unlock()
			
		default:
			addEvent("WARN", client.ID, "Comando no reconocido: "+line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		addEvent("ERROR", client.ID, "Error de lectura: "+err.Error())
	}
	
	close(stopPing)
}

// *************** SERVIDORES TCP/TLS ***************
func startServer() {
	var listener net.Listener
	var err error
	
	if config.EnableTLS {
		cert, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
		if err != nil {
			log.Fatalf("[FATAL] Error cargando certificados TLS: %v", err)
		}
		
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}
		
		listener, err = tls.Listen("tcp", config.ListenAddr, tlsConfig)
		addEvent("INFO", "", "Servidor TLS iniciado en "+config.ListenAddr)
	} else {
		listener, err = net.Listen("tcp", config.ListenAddr)
		addEvent("INFO", "", "Servidor TCP iniciado en "+config.ListenAddr)
	}
	
	if err != nil {
		log.Fatalf("[FATAL] Error al iniciar servidor: %v", err)
	}
	
	defer listener.Close()
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			addEvent("ERROR", "", "Error aceptando conexión: "+err.Error())
			continue
		}
		go handleClient(conn)
	}
}

// *************** FUNCIONES DE GESTIÓN ***************
func broadcastCommand(command string) int {
	muClients.RLock()
	defer muClients.RUnlock()
	
	count := 0
	for _, client := range clients {
		client.mu.Lock()
		if _, err := client.Conn.Write([]byte(command + "\n")); err == nil {
			count++
		}
		client.mu.Unlock()
	}
	
	addEvent("INFO", "", fmt.Sprintf("Broadcast: '%s' a %d clientes", command, count))
	return count
}

func kickClient(clientID string) bool {
	muClients.RLock()
	client, exists := clients[clientID]
	muClients.RUnlock()
	
	if exists {
		client.Conn.Close()
		stats.Lock()
		stats.Kicked++
		stats.Unlock()
		return true
	}
	return false
}

func listClients() []Client {
	muClients.RLock()
	defer muClients.RUnlock()
	
	clientList := make([]Client, 0, len(clients))
	for _, c := range clients {
		c.mu.Lock()
		clientCopy := *c
		c.mu.Unlock()
		clientList = append(clientList, clientCopy)
	}
	return clientList
}

// *************** PANEL WEB Y API ***************
func panelHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
	
	csrfToken := generateCSRFToken()
	
	// Plantilla HTML completamente corregida y validada
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ChaosWAF Control Panel</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .card { background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; }
        .stat-box { background: #e3f2fd; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; }
        table { width: 100%%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .online { color: #4CAF50; }
        .offline { color: #f44336; }
        .event-row { margin-bottom: 8px; padding: 8px; border-left: 3px solid #2196F3; background: #e3f2fd; }
        .event-warn { border-left-color: #ff9800; background: #fff3e0; }
        .event-error { border-left-color: #f44336; background: #ffebee; }
        .controls { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        input, button { padding: 10px 15px; border-radius: 4px; }
        input { border: 1px solid #ddd; flex-grow: 1; }
        button { background: #2196F3; color: white; border: none; cursor: pointer; }
        button:hover { background: #0b7dda; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ChaosWAF Control Panel</h1>
            <p>Monitoreo y gestión en tiempo real</p>
        </div>
        
        <div class="card">
            <h2>Estadísticas del Sistema</h2>
            <div class="stats-grid" id="stats-container">
                <!-- Las estadísticas se cargarán dinámicamente -->
            </div>
        </div>
        
        <div class="card">
            <div class="controls">
                <input type="text" id="broadcast-cmd" placeholder="Comando para broadcast">
                <input type="number" id="disperse-percent" min="1" max="100" value="100" placeholder="%%">
                <button onclick="sendBroadcast()">Enviar Comando</button>
                <input type="text" id="client-id" placeholder="ID Cliente">
                <button onclick="kickClient()">Expulsar Cliente</button>
            </div>
        </div>
        
        <div class="card">
            <h2>Clientes Conectados <span id="client-count"></span></h2>
            <div id="clients-container">
                <!-- Los clientes se cargarán dinámicamente -->
            </div>
        </div>
        
        <div class="card">
            <h2>Eventos Recientes</h2>
            <div id="events-container">
                <!-- Los eventos se cargarán dinámicamente -->
            </div>
        </div>
    </div>
    
    <input type="hidden" id="csrf-token" value="%s">
    
    <script>
        const csrfToken = document.getElementById('csrf-token').value;
        
        function secureFetch(url, options) {
            if (!options) options = {};
            if (!options.headers) options.headers = {};
            options.headers['X-CSRF-Token'] = csrfToken;
            return fetch(url, options);
        }
        
        function updateData() {
            secureFetch('/api/stats')
                .then(function(r) { return r.json(); })
                .then(updateStats);
            
            secureFetch('/api/clients')
                .then(function(r) { return r.json(); })
                .then(updateClients);
            
            secureFetch('/api/events')
                .then(function(r) { return r.json(); })
                .then(updateEvents);
        }
        
        setInterval(updateData, 5000);
        updateData();
        
        function updateStats(stats) {
            const container = document.getElementById('stats-container');
            container.innerHTML = ''
                + '<div class="stat-box">'
                +   '<div class="stat-label">Conexiones Totales</div>'
                +   '<div class="stat-value">' + stats.total_connections + '</div>'
                + '</div>'
                + '<div class="stat-box">'
                +   '<div class="stat-label">Clientes Activos</div>'
                +   '<div class="stat-value">' + stats.current_clients + '</div>'
                + '</div>'
                + '<div class="stat-box">'
                +   '<div class="stat-label">Autenticaciones</div>'
                +   '<div class="stat-value">' + stats.auth_accepted + '/' + stats.auth_rejected + '</div>'
                + '</div>'
                + '<div class="stat-box">'
                +   '<div class="stat-label">Comandos Ejecutados</div>'
                +   '<div class="stat-value">' + stats.commands_executed + '</div>'
                + '</div>'
                + '<div class="stat-box">'
                +   '<div class="stat-label">Expulsados/Timeouts</div>'
                +   '<div class="stat-value">' + stats.kicked + '/' + stats.timeouts + '</div>'
                + '</div>';
        }
        
        function updateClients(clients) {
            const container = document.getElementById('clients-container');
            const countSpan = document.getElementById('client-count');
            countSpan.textContent = '(' + clients.length + ')';
            
            let html = '<table>'
                + '<tr>'
                +   '<th>ID</th>'
                +   '<th>Dirección</th>'
                +   '<th>Estado</th>'
                +   '<th>Última Actividad</th>'
                + '</tr>';
            
            clients.forEach(function(client) {
                const statusClass = client.health === 'healthy' ? 'online' : 'offline';
                html += '<tr>'
                    + '<td>' + client.id + '</td>'
                    + '<td>' + client.remote + '</td>'
                    + '<td class="' + statusClass + '">' + client.health + '</td>'
                    + '<td>' + new Date(client.last_seen).toLocaleString() + '</td>'
                    + '</tr>';
            });
            
            html += '</table>';
            container.innerHTML = clients.length > 0 ? html : '<p>No hay clientes conectados</p>';
        }
        
        function updateEvents(events) {
            const container = document.getElementById('events-container');
            
            let html = '';
            events.forEach(function(event) {
                let levelClass = '';
                if (event.level.toLowerCase() === 'warn') levelClass = 'event-warn';
                if (event.level.toLowerCase() === 'error') levelClass = 'event-error';
                
                html += '<div class="event-row ' + levelClass + '">'
                    + '<strong>[' + new Date(event.ts).toLocaleString() + '] [' + event.level + ']</strong> '
                    + (event.client ? '[' + event.client + '] ' : '')
                    + event.message
                    + '</div>';
            });
            
            container.innerHTML = html || '<p>No hay eventos recientes</p>';
        }
        
        function sendBroadcast() {
            const cmd = document.getElementById('broadcast-cmd').value;
            const percent = document.getElementById('disperse-percent').value;
            
            if (cmd) {
                secureFetch('/broadcast?cmd=' + encodeURIComponent(cmd) + '&percent=' + percent)
                    .then(function(response) {
                        if (!response.ok) {
                            alert('Error: ' + response.statusText);
                        }
                    });
            }
        }
        
        function kickClient() {
            const clientId = document.getElementById('client-id').value;
            if (clientId) {
                secureFetch('/kick?id=' + encodeURIComponent(clientId))
                    .then(function(response) {
                        if (!response.ok) {
                            alert('Error: ' + response.statusText);
                        }
                    });
            }
        }
    </script>
</body>
</html>`, csrfToken)
	
	fmt.Fprint(w, html)
}

func startPanel() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", basicAuth(panelHandler))
	mux.HandleFunc("/api/clients", basicAuth(apiClientsHandler))
	mux.HandleFunc("/api/events", basicAuth(apiEventsHandler))
	mux.HandleFunc("/api/stats", basicAuth(apiStatsHandler))
	mux.HandleFunc("/broadcast", basicAuth(broadcastHandler))
	mux.HandleFunc("/kick", basicAuth(kickHandler))
	
	server := &http.Server{
		Addr:         config.PanelAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	
	addEvent("INFO", "", "Panel web iniciado en http://localhost"+config.PanelAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] Error al iniciar panel: %v", err)
	}
}

// *************** HANDLERS DE API ***************
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if config.PanelUsername == "" || config.PanelPassword == "" {
			next.ServeHTTP(w, r)
			return
		}
		
		user, pass, ok := r.BasicAuth()
		if !ok || user != config.PanelUsername || pass != config.PanelPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="ChaosWAF Panel"`)
			http.Error(w, "Acceso no autorizado", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func validateCSRFHeader(r *http.Request) bool {
	token := r.Header.Get("X-CSRF-Token")
	return validateCSRFToken(token)
}

func apiClientsHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRFHeader(r) {
		http.Error(w, "Token CSRF inválido", http.StatusForbidden)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listClients())
}

func apiEventsHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRFHeader(r) {
		http.Error(w, "Token CSRF inválido", http.StatusForbidden)
		return
	}
	
	muEvents.RLock()
	defer muEvents.RUnlock()
	
	// Devolver solo los últimos 50 eventos
	start := 0
	if len(events) > 50 {
		start = len(events) - 50
	}
	eventsToSend := events[start:]
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(eventsToSend)
}

func apiStatsHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRFHeader(r) {
		http.Error(w, "Token CSRF inválido", http.StatusForbidden)
		return
	}
	
	stats.Lock()
	defer stats.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func broadcastHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRFHeader(r) {
		http.Error(w, "Token CSRF inválido", http.StatusForbidden)
		return
	}
	
	cmd := r.URL.Query().Get("cmd")
	percent, _ := strconv.Atoi(r.URL.Query().Get("percent"))
	
	if cmd == "" {
		http.Error(w, "Parámetro 'cmd' requerido", http.StatusBadRequest)
		return
	}
	
	count := disperseCommand(cmd, percent)
	fmt.Fprintf(w, "Comando dispersado a %d clientes", count)
}

func kickHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRFHeader(r) {
		http.Error(w, "Token CSRF inválido", http.StatusForbidden)
		return
	}
	
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		http.Error(w, "Parámetro 'id' requerido", http.StatusBadRequest)
		return
	}
	
	if kickClient(clientID) {
		fmt.Fprint(w, "Cliente expulsado")
	} else {
		http.Error(w, "Cliente no encontrado", http.StatusNotFound)
	}
}

// *************** PERSISTENCIA DE DATOS ***************
func saveData() {
	muEvents.RLock()
	eventsData, _ := json.Marshal(events)
	muEvents.RUnlock()
	os.WriteFile("events.json", eventsData, 0644)
	
	stats.Lock()
	statsData, _ := json.Marshal(stats)
	stats.Unlock()
	os.WriteFile("stats.json", statsData, 0644)
	
	addEvent("INFO", "", "Datos guardados en disco")
}

func loadData() {
	if data, err := os.ReadFile("events.json"); err == nil {
		json.Unmarshal(data, &events)
	}
	
	if data, err := os.ReadFile("stats.json"); err == nil {
		json.Unmarshal(data, &stats)
	}
}

func persistenceLoop() {
	ticker := time.NewTicker(config.PersistInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			saveData()
		case <-stopChan:
			saveData()
			return
		}
	}
}

// *************** CONSOLA DE ADMINISTRACIÓN ***************
func adminConsole() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("ChaosWAF Admin Console")
	fmt.Println("Comandos: list | stats | broadcast <cmd> [%%] | kick <id> | exit")
	
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		
		cmd := strings.TrimSpace(scanner.Text())
		if cmd == "" {
			continue
		}
		
		parts := strings.Fields(cmd)
		switch parts[0] {
		case "list":
			clients := listClients()
			fmt.Printf("\nClientes conectados (%d):\n", len(clients))
			for _, c := range clients {
				fmt.Printf("- %s (%s) [%s] %s\n", c.ID, c.Remote, c.Health, c.LastSeen.Format(time.RFC3339))
			}
			
		case "stats":
			stats.Lock()
			fmt.Printf("\nEstadísticas:\n")
			fmt.Printf("Conexiones totales: %d\n", stats.TotalConnections)
			fmt.Printf("Clientes activos:   %d\n", stats.CurrentClients)
			fmt.Printf("Autenticaciones:    %d/%d\n", stats.AuthAccepted, stats.AuthRejected)
			fmt.Printf("Comandos ejecutados: %d\n", stats.CommandsExecuted)
			fmt.Printf("Expulsados:         %d\n", stats.Kicked)
			fmt.Printf("Timeouts:           %d\n", stats.TimeOuts)
			stats.Unlock()
			
		case "broadcast":
			if len(parts) < 2 {
				fmt.Println("Uso: broadcast <comando> [porcentaje]")
				continue
			}
			
			percent := 100
			if len(parts) >= 3 {
				if p, err := strconv.Atoi(parts[2]); err == nil && p > 0 && p <= 100 {
					percent = p
				}
			}
			
			command := strings.Join(parts[1:], " ")
			count := disperseCommand(command, percent)
			fmt.Printf("Comando enviado a %d clientes\n", count)
			
		case "kick":
			if len(parts) < 2 {
				fmt.Println("Uso: kick <client-id>")
				continue
			}
			if kickClient(parts[1]) {
				fmt.Println("Cliente expulsado")
			} else {
				fmt.Println("Cliente no encontrado")
			}
			
		case "exit":
			fmt.Println("Saliendo...")
			close(stopChan)
			os.Exit(0)
			
		default:
			fmt.Println("Comando no reconocido")
		}
	}
}

// *************** FUNCIÓN PRINCIPAL ***************
func main() {
	setupLogging()
	loadData()
	
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		addEvent("INFO", "", "Recibida señal de terminación")
		close(stopChan)
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
	
	go persistenceLoop()
	
	log.Println("Iniciando ChaosWAF Server")
	log.Printf("Modo TLS: %v", config.EnableTLS)
	log.Printf("Clientes máximos en memoria: %d", eventsMax)
	log.Printf("Clave secreta: %s", config.SecretKey[:8]+"****")
	
	go startServer()
	go startPanel()
	
	adminConsole()
}
