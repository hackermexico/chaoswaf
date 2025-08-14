package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultListen = ":4000" // Puerto para clientes
	defaultPanel  = ":8081" // Panel web / API
	logFileName   = "server_chaoswaf.log"
	eventsMax     = 2000    // Máx eventos en memoria antes de rotar
	pingInterval  = 30 * time.Second
	pongTimeout   = 20 * time.Second
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
	Health       string      `json:"health"` // healthy | unverified | timeout
	PendingPong  bool        `json:"pending_pong"`
	Tags         []string    `json:"tags,omitempty"`
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
}

var (
	clients    = make(map[string]*Client)
	muClients  sync.Mutex
	events     []Event
	muEvents   sync.Mutex
	stats      Stats

	// Config
	listenAddr = getenv("CHAOS_LISTEN", defaultListen)
	panelAddr  = getenv("CHAOS_PANEL", defaultPanel)
	// AUTH_TOKENS format: "tokenName1:secret1,tokenName2:secret2"
	authTokens = parseTokens(getenv("CHAOS_AUTH_TOKENS", ""))

	// logging
	logW io.Writer
)

// ------------- Utilidades de Config y Logging -------------

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseTokens(raw string) map[string]string {
	m := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return m
	}
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || !strings.Contains(p, ":") {
			continue
		}
		name := strings.TrimSpace(strings.SplitN(p, ":", 2)[0])
		secret := strings.TrimSpace(strings.SplitN(p, ":", 2)[1])
		if name != "" && secret != "" {
			m[name] = secret
		}
	}
	return m
}

func setupLogging() {
	f, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("[WARN] no se pudo abrir log de archivo, usando solo stdout:", err)
		logW = os.Stdout
		return
	}
	logW = io.MultiWriter(os.Stdout, f)
	log.SetOutput(logW)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

func addEvent(level, clientID, msg string) {
	e := Event{TS: time.Now(), Level: level, Client: clientID, Message: msg}
	muEvents.Lock()
	defer muEvents.Unlock()
	events = append(events, e)
	if len(events) > eventsMax {
		// rotación simple: conserva la mitad más reciente
		events = slices.Clone(events[len(events)/2:])
	}
	fmt.Fprintf(logW, "[%s][%s] %s\n", level, clientID, msg)
}

// ------------- Gestión de Clientes -------------

func registerClient(conn net.Conn) *Client {
	id := conn.RemoteAddr().String()
	c := &Client{
		ID:          id,
		Remote:      id,
		Authed:      false,
		Conn:        conn,
		LastSeen:    time.Now(),
		ConnectedAt: time.Now(),
		Health:      "unverified",
	}
	muClients.Lock()
	clients[id] = c
	stats.Lock()
	stats.TotalConnections++
	stats.CurrentClients = len(clients)
	stats.Unlock()
	muClients.Unlock()
	addEvent("INFO", c.ID, "cliente conectado")
	return c
}

func unregisterClient(c *Client, reason string) {
	muClients.Lock()
	delete(clients, c.ID)
	stats.Lock()
	stats.CurrentClients = len(clients)
	stats.Unlock()
	muClients.Unlock()
	_ = c.Conn.Close()
	addEvent("INFO", c.ID, "cliente desconectado: "+reason)
}

func tryAuth(line string, c *Client) bool {
	// Formato esperado: AUTH <tokenName> <tokenSecret> [clientTag1,clientTag2...]
	// Backward compatible: si no empieza con AUTH, no forzamos auth.
	if !strings.HasPrefix(line, "AUTH ") {
		addEvent("WARN", c.ID, "cliente legacy sin AUTH; continuando sin autenticación")
		return true
	}
	parts := strings.Fields(line)
	if len(parts) < 3 {
		addEvent("ERROR", c.ID, "AUTH inválido (faltan parámetros)")
		return false
	}
	name := parts[1]
	secret := parts[2]
	if want, ok := authTokens[name]; ok && want == secret {
		c.mu.Lock()
		c.Authed = true
		c.TokenName = name
		// etiquetas opcionales
		if len(parts) >= 4 {
			tags := strings.Split(parts[3], ",")
			c.Tags = nil
			for _, t := range tags {
				t = strings.TrimSpace(t)
				if t != "" {
					c.Tags = append(c.Tags, t)
				}
			}
		}
		c.mu.Unlock()
		stats.Lock()
		stats.AuthAccepted++
		stats.Unlock()
		addEvent("INFO", c.ID, "autenticado con token "+name)
		return true
	}
	stats.Lock()
	stats.AuthRejected++
	stats.Unlock()
	addEvent("ERROR", c.ID, "AUTH rechazado para token "+name)
	return false
}

// ------------- Manejadores TCP -------------

func handleClient(conn net.Conn) {
	c := registerClient(conn)
	defer unregisterClient(c, "fin de sesión")

	// Goroutine PING
	stopPing := make(chan struct{})
	go func() {
		t := time.NewTicker(pingInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				c.mu.Lock()
				c.PendingPong = true
				c.mu.Unlock()
				_, _ = c.Conn.Write([]byte("PING\n"))
				// timeout checker
				go func(ref *Client) {
					time.Sleep(pongTimeout)
					ref.mu.Lock()
					defer ref.mu.Unlock()
					if ref.PendingPong {
						ref.Health = "timeout"
						stats.Lock()
						stats.TimeOuts++
						stats.Unlock()
						addEvent("WARN", ref.ID, "timeout de PONG")
					}
				}(c)
			case <-stopPing:
				return
			}
		}
	}()

	sc := bufio.NewScanner(conn)
	firstLine := true

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		c.mu.Lock()
		c.LastSeen = time.Now()
		c.mu.Unlock()

		// Primer línea: intentamos AUTH (si viene)
		if firstLine {
			firstLine = false
			if ok := tryAuth(line, c); !ok {
				_, _ = c.Conn.Write([]byte("ERR AUTH\n"))
				return
			}
			// si era AUTH y pasó, sigue; si era legacy, lo tratamos como reporte
			if strings.HasPrefix(line, "AUTH ") {
				_, _ = c.Conn.Write([]byte("OK AUTH\n"))
				continue
			}
		}

		// PONG
		if line == "PONG" {
			c.mu.Lock()
			c.PendingPong = false
			c.Health = "healthy"
			c.mu.Unlock()
			addEvent("DEBUG", c.ID, "PONG recibido")
			continue
		}

		// Procesamos “reportes” genéricos del cliente (legacy o nuevo)
		c.mu.Lock()
		c.LastReport = line
		c.mu.Unlock()
		addEvent("REPORT", c.ID, line)
	}

	if err := sc.Err(); err != nil {
		addEvent("ERROR", c.ID, "error de lectura: "+err.Error())
	}

	close(stopPing)
}

// ------------- Servidor TCP y Consola -------------

func startTCPServer() {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("[FATAL] no se pudo iniciar servidor TCP en %s: %v", listenAddr, err)
	}
	addEvent("INFO", "", "Servidor TCP escuchando en "+listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			addEvent("WARN", "", "error aceptando conexión: "+err.Error())
			continue
		}
		go handleClient(conn)
	}
}

func broadcast(cmd string) int {
	muClients.Lock()
	defer muClients.Unlock()
	count := 0
	for _, c := range clients {
		_, err := c.Conn.Write([]byte(cmd + "\n"))
		if err == nil {
			count++
		}
	}
	addEvent("INFO", "", fmt.Sprintf("broadcast '%s' a %d clientes", cmd, count))
	return count
}

func kick(id string) bool {
	muClients.Lock()
	defer muClients.Unlock()
	if c, ok := clients[id]; ok {
		_ = c.Conn.Close()
		stats.Lock()
		stats.Kicked++
		stats.Unlock()
		return true
	}
	return false
}

func listClients() []Client {
	muClients.Lock()
	defer muClients.Unlock()
	out := make([]Client, 0, len(clients))
	for _, c := range clients {
		c.mu.Lock()
		cp := *c
		c.mu.Unlock()
		out = append(out, cp)
	}
	return out
}

// ------------- Panel Web / API -------------

func panelIndex(w http.ResponseWriter, r *http.Request) {
	// página simple
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<html><head><title>ChaosWAF Central</title>
<style>body{font-family:system-ui,Segoe UI,Arial;margin:24px} code{background:#f5f5f5;padding:2px 6px;border-radius:6px}</style>
</head><body>
<h2>ChaosWAF Central</h2>
<p><b>Clientes:</b> <a href="/api/clients">/api/clients</a> | <b>Eventos:</b> <a href="/api/events">/api/events</a> | <b>Stats:</b> <a href="/api/stats">/api/stats</a></p>
<p>Broadcast rápido: <a href="/broadcast?cmd=caos">caos</a> · <a href="/broadcast?cmd=burst">burst</a></p>
<p>Kick (ejemplo): <code>GET /kick?id=CLIENT_ID</code></p>
<hr>
<h3>Clientes Conectados</h3>
<pre>%s</pre>
<h3>Últimos Eventos</h3>
<pre>%s</pre>
</body></html>`,
	summarizeClientsForHTML(), summarizeEventsForHTML(50))
}

func apiClients(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, listClients())
}

func apiEvents(w http.ResponseWriter, r *http.Request) {
	muEvents.Lock()
	defer muEvents.Unlock()
	writeJSON(w, events)
}

func apiStats(w http.ResponseWriter, r *http.Request) {
	stats.Lock()
	defer stats.Unlock()
	writeJSON(w, stats)
}

func hBroadcast(w http.ResponseWriter, r *http.Request) {
	cmd := strings.TrimSpace(r.URL.Query().Get("cmd"))
	if cmd == "" {
		http.Error(w, "missing cmd", http.StatusBadRequest)
		return
	}
	n := broadcast(cmd)
	fmt.Fprintf(w, "OK %d\n", n)
}

func hKick(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if kick(id) {
		fmt.Fprintln(w, "OK")
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func startPanel() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", panelIndex)
	mux.HandleFunc("/api/clients", apiClients)
	mux.HandleFunc("/api/events", apiEvents)
	mux.HandleFunc("/api/stats", apiStats)
	mux.HandleFunc("/broadcast", hBroadcast)
	mux.HandleFunc("/kick", hKick)

	srv := &http.Server{
		Addr:              panelAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	addEvent("INFO", "", "Panel web en http://localhost"+panelAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[ERROR] panel: %v", err)
	}
}

// ------------- Utilidades Panel -------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func summarizeClientsForHTML() string {
	ls := listClients()
	var b strings.Builder
	if len(ls) == 0 {
		return "No hay clientes conectados."
	}
	for _, c := range ls {
		fmt.Fprintf(&b, "ID: %s\nRemote: %s\nAuthed: %t (%s)\nHealth: %s\nLastSeen: %s\nLastReport: %s\nTags: %v\n---\n",
			c.ID, c.Remote, c.Authed, c.TokenName, c.Health, c.LastSeen.Format(time.RFC3339), c.LastReport, c.Tags)
	}
	return b.String()
}

func summarizeEventsForHTML(max int) string {
	muEvents.Lock()
	defer muEvents.Unlock()
	if len(events) == 0 {
		return "Sin eventos."
	}
	start := 0
	if len(events) > max {
		start = len(events) - max
	}
	var b strings.Builder
	for _, e := range events[start:] {
		fmt.Fprintf(&b, "%s [%s] (%s) %s\n", e.TS.Format("15:04:05"), e.Level, e.Client, e.Message)
	}
	return b.String()
}

// ------------- Consola Interactiva -------------

func startConsole() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("ChaosWAF> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		args := strings.Fields(line)
		switch args[0] {
		case "help":
			fmt.Println("Comandos: help | list | stats | broadcast <cmd> | kick <clientID> | exit")
		case "list":
			ls := listClients()
			if len(ls) == 0 {
				fmt.Println("No hay clientes conectados")
			} else {
				for _, c := range ls {
					fmt.Printf("- %s (%s) authed=%t health=%s last=%s\n",
						c.ID, c.Remote, c.Authed, c.Health, c.LastSeen.Format("15:04:05"))
				}
			}
		case "stats":
			stats.Lock()
			fmt.Printf("Conexiones: total=%d actuales=%d auth_ok=%d auth_bad=%d kicked=%d timeouts=%d\n",
				stats.TotalConnections, stats.CurrentClients, stats.AuthAccepted, stats.AuthRejected, stats.Kicked, stats.TimeOuts)
			stats.Unlock()
		case "broadcast":
			if len(args) < 2 {
				fmt.Println("Uso: broadcast <cmd>")
				continue
			}
			cmd := strings.Join(args[1:], " ")
			n := broadcast(cmd)
			fmt.Printf("OK: enviado a %d clientes\n", n)
		case "kick":
			if len(args) < 2 {
				fmt.Println("Uso: kick <clientID>")
				continue
			}
			if kick(args[1]) {
				fmt.Println("OK")
			} else {
				fmt.Println("No encontrado")
			}
		case "exit":
			fmt.Println("Cerrando servidor...")
			os.Exit(0)
		default:
			fmt.Println("Comando desconocido. Usa 'help'")
		}
	}
}

// ------------- Main -------------

func main() {
	setupLogging()

	// Señales para cierre limpio
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)

	go startTCPServer()
	go startPanel()
	go func() {
		<-sigc
		addEvent("INFO", "", "señal de cierre recibida; saliendo")
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}()

	// Info inicial
	if len(authTokens) == 0 {
		addEvent("WARN", "", "sin tokens de autenticación configurados (modo abierto/legacy)")
	} else {
		addEvent("INFO", "", fmt.Sprintf("auth habilitado: %d tokens cargados", len(authTokens)))
	}

	startConsole()
}
