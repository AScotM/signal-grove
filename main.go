package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	version                  = "1.2.2"
	maxRequestBody           = 64 * 1024
	defaultAddr              = ":8080"
	defaultHistory           = 10000
	defaultWindow            = 60
	defaultThreshold         = 3.0
	defaultMinSamples        = 10
	defaultAbsoluteTolerance = 0.001
	defaultRelativeTolerance = 0.01
	defaultMaxAge            = 24 * time.Hour
)

type Event struct {
	ID        uint64    `json:"id"`
	Node      string    `json:"node"`
	Signal    string    `json:"signal"`
	Value     float64   `json:"value"`
	Timestamp time.Time `json:"timestamp"`
	Anomaly   bool      `json:"anomaly"`
	ZScore    *float64  `json:"z_score"`
	Mean      float64   `json:"mean"`
	StdDev    float64   `json:"std_dev"`
	Samples   int       `json:"samples"`
	Learned   bool      `json:"learned"`
}

type IncomingEvent struct {
	Node      string     `json:"node"`
	Signal    string     `json:"signal"`
	Value     float64    `json:"value"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

type SignalSample struct {
	Value     float64
	Timestamp time.Time
}

type SignalState struct {
	Node        string    `json:"node"`
	Signal      string    `json:"signal"`
	Value       float64   `json:"value"`
	Mean        float64   `json:"mean"`
	StdDev      float64   `json:"std_dev"`
	ZScore      *float64  `json:"z_score"`
	Samples     int       `json:"samples"`
	Anomaly     bool      `json:"anomaly"`
	Learned     bool      `json:"learned"`
	LastUpdated time.Time `json:"last_updated"`
}

type NodeState struct {
	Name          string                 `json:"name"`
	LastSeen      time.Time              `json:"last_seen"`
	EventCount    uint64                 `json:"event_count"`
	AnomalyCount  uint64                 `json:"anomaly_count"`
	ActiveAnomaly int                    `json:"active_anomalies"`
	Signals       map[string]SignalState `json:"signals"`
}

type Status struct {
	Name              string    `json:"name"`
	Version           string    `json:"version"`
	StartedAt         time.Time `json:"started_at"`
	UptimeSeconds     int64     `json:"uptime_seconds"`
	Nodes             int       `json:"nodes"`
	Signals           int       `json:"signals"`
	Events            int       `json:"events"`
	ActiveAnomalies   int       `json:"active_anomalies"`
	TotalReceived     uint64    `json:"total_received"`
	TotalAnomalies    uint64    `json:"total_anomalies"`
	RejectedEvents    uint64    `json:"rejected_events"`
	HistoryLimit      int       `json:"history_limit"`
	BaselineWindow    int       `json:"baseline_window"`
	MinimumSamples    int       `json:"minimum_samples"`
	AnomalyZScore     float64   `json:"anomaly_z_score"`
	AbsoluteTolerance float64   `json:"absolute_tolerance"`
	RelativeTolerance float64   `json:"relative_tolerance"`
	MaximumEventAge   string    `json:"maximum_event_age"`
	CurrentTime       time.Time `json:"current_time"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type Config struct {
	Addr              string
	HistoryLimit      int
	Window            int
	Threshold         float64
	MinSamples        int
	AbsoluteTolerance float64
	RelativeTolerance float64
	MaxAge            time.Duration
	Dashboard         bool
	DashboardRate     time.Duration
}

type Grove struct {
	mu                sync.RWMutex
	events            []Event
	histories         map[string][]SignalSample
	states            map[string]SignalState
	nodes             map[string]*NodeState
	historyLimit      int
	window            int
	threshold         float64
	minSamples        int
	absoluteTolerance float64
	relativeTolerance float64
	maxAge            time.Duration
	startedAt         time.Time
	nextID            atomic.Uint64
	totalReceived     atomic.Uint64
	totalAnomalies    atomic.Uint64
	rejected          atomic.Uint64
}

func NewGrove(cfg Config) *Grove {
	return &Grove{
		events:            make([]Event, 0, min(cfg.HistoryLimit, 1024)),
		histories:         make(map[string][]SignalSample),
		states:            make(map[string]SignalState),
		nodes:             make(map[string]*NodeState),
		historyLimit:      cfg.HistoryLimit,
		window:            cfg.Window,
		threshold:         cfg.Threshold,
		minSamples:        cfg.MinSamples,
		absoluteTolerance: cfg.AbsoluteTolerance,
		relativeTolerance: cfg.RelativeTolerance,
		maxAge:            cfg.MaxAge,
		startedAt:         time.Now(),
	}
}

func signalKey(node, signal string) string {
	return node + "\x00" + signal
}

func validateName(value string, field string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", field)
	}

	if len(value) > 128 {
		return fmt.Errorf("%s exceeds 128 characters", field)
	}

	for _, r := range value {
		if r < 32 || r == 127 {
			return fmt.Errorf("%s contains control characters", field)
		}
	}

	return nil
}

func validateIncomingEvent(event IncomingEvent, maxAge time.Duration) error {
	if err := validateName(event.Node, "node"); err != nil {
		return err
	}

	if err := validateName(event.Signal, "signal"); err != nil {
		return err
	}

	if math.IsNaN(event.Value) || math.IsInf(event.Value, 0) {
		return errors.New("value must be a finite number")
	}

	if event.Timestamp != nil {
		now := time.Now()

		if event.Timestamp.After(now.Add(5 * time.Minute)) {
			return errors.New("timestamp is too far in the future")
		}

		if maxAge > 0 && event.Timestamp.Before(now.Add(-maxAge)) {
			return errors.New("timestamp is older than maximum event age")
		}
	}

	return nil
}

func calculateStats(samples []SignalSample) (float64, float64) {
	if len(samples) == 0 {
		return 0, 0
	}

	var sum float64

	for _, sample := range samples {
		sum += sample.Value
	}

	mean := sum / float64(len(samples))

	if len(samples) < 2 {
		return mean, 0
	}

	var squared float64

	for _, sample := range samples {
		difference := sample.Value - mean
		squared += difference * difference
	}

	variance := squared / float64(len(samples)-1)

	if variance < 0 {
		variance = 0
	}

	return mean, math.Sqrt(variance)
}

func calculateZScore(value, mean, stdDev float64) float64 {
	return (value - mean) / stdDev
}

func exceedsTolerance(
	value,
	mean,
	absoluteTolerance,
	relativeTolerance float64,
) bool {
	difference := math.Abs(value - mean)
	scale := math.Max(math.Abs(mean), math.Abs(value))

	tolerance := math.Max(
		absoluteTolerance,
		relativeTolerance*scale,
	)

	return difference > tolerance
}

func floatPointer(value float64) *float64 {
	result := value
	return &result
}

func (g *Grove) detectAnomaly(
	value float64,
	history []SignalSample,
) (bool, *float64, float64, float64, int) {
	mean, stdDev := calculateStats(history)
	samples := len(history)

	if samples < g.minSamples {
		return false, nil, mean, stdDev, samples
	}

	if stdDev > 0 {
		zScore := calculateZScore(value, mean, stdDev)
		anomaly := math.Abs(zScore) >= g.threshold

		return anomaly, floatPointer(zScore), mean, stdDev, samples
	}

	anomaly := exceedsTolerance(
		value,
		mean,
		g.absoluteTolerance,
		g.relativeTolerance,
	)

	return anomaly, nil, mean, stdDev, samples
}

func (g *Grove) Add(in IncomingEvent) (Event, error) {
	in.Node = strings.TrimSpace(in.Node)
	in.Signal = strings.TrimSpace(in.Signal)

	if err := validateIncomingEvent(in, g.maxAge); err != nil {
		g.rejected.Add(1)
		return Event{}, err
	}

	timestamp := time.Now().UTC()

	if in.Timestamp != nil {
		timestamp = in.Timestamp.UTC()
	}

	key := signalKey(in.Node, in.Signal)

	g.mu.Lock()
	defer g.mu.Unlock()

	history := g.histories[key]

	if len(history) > g.window {
		history = history[len(history)-g.window:]
	}

	anomaly, zScore, mean, stdDev, samples := g.detectAnomaly(
		in.Value,
		history,
	)

	learned := !anomaly
	id := g.nextID.Add(1)

	event := Event{
		ID:        id,
		Node:      in.Node,
		Signal:    in.Signal,
		Value:     in.Value,
		Timestamp: timestamp,
		Anomaly:   anomaly,
		ZScore:    zScore,
		Mean:      mean,
		StdDev:    stdDev,
		Samples:   samples,
		Learned:   learned,
	}

	g.events = append(g.events, event)

	if len(g.events) > g.historyLimit {
		excess := len(g.events) - g.historyLimit
		copy(g.events, g.events[excess:])
		g.events = g.events[:g.historyLimit]
	}

	if learned {
		history = append(history, SignalSample{
			Value:     in.Value,
			Timestamp: timestamp,
		})

		if len(history) > g.window {
			history = history[len(history)-g.window:]
		}

		g.histories[key] = history
	}

	baselineHistory := g.histories[key]
	updatedMean, updatedStdDev := calculateStats(baselineHistory)

	state := SignalState{
		Node:        in.Node,
		Signal:      in.Signal,
		Value:       in.Value,
		Mean:        updatedMean,
		StdDev:      updatedStdDev,
		ZScore:      zScore,
		Samples:     len(baselineHistory),
		Anomaly:     anomaly,
		Learned:     learned,
		LastUpdated: timestamp,
	}

	g.states[key] = state

	node, exists := g.nodes[in.Node]

	if !exists {
		node = &NodeState{
			Name:    in.Node,
			Signals: make(map[string]SignalState),
		}

		g.nodes[in.Node] = node
	}

	node.LastSeen = timestamp
	node.EventCount++

	if anomaly {
		node.AnomalyCount++
		g.totalAnomalies.Add(1)
	}

	node.Signals[in.Signal] = state
	g.recalculateNodeAnomalies(node)
	g.totalReceived.Add(1)

	return event, nil
}

func (g *Grove) recalculateNodeAnomalies(node *NodeState) {
	node.ActiveAnomaly = 0

	for _, state := range node.Signals {
		if state.Anomaly {
			node.ActiveAnomaly++
		}
	}
}

func (g *Grove) Events(limit int) []Event {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if limit <= 0 || limit > len(g.events) {
		limit = len(g.events)
	}

	start := len(g.events) - limit
	result := make([]Event, limit)
	copy(result, g.events[start:])

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

func (g *Grove) Anomalies(limit int) []Event {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]Event, 0)

	for i := len(g.events) - 1; i >= 0; i-- {
		if g.events[i].Anomaly {
			result = append(result, g.events[i])

			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}

	return result
}

func (g *Grove) Nodes() []NodeState {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]NodeState, 0, len(g.nodes))

	for _, node := range g.nodes {
		copyNode := NodeState{
			Name:          node.Name,
			LastSeen:      node.LastSeen,
			EventCount:    node.EventCount,
			AnomalyCount:  node.AnomalyCount,
			ActiveAnomaly: node.ActiveAnomaly,
			Signals:       make(map[string]SignalState, len(node.Signals)),
		}

		for name, state := range node.Signals {
			copyNode.Signals[name] = state
		}

		result = append(result, copyNode)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}

func (g *Grove) Signals() []SignalState {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]SignalState, 0, len(g.states))

	for _, state := range g.states {
		result = append(result, state)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Node == result[j].Node {
			return result[i].Signal < result[j].Signal
		}

		return result[i].Node < result[j].Node
	})

	return result
}

func (g *Grove) Status() Status {
	g.mu.RLock()

	nodes := len(g.nodes)
	signals := len(g.states)
	events := len(g.events)
	activeAnomalies := 0

	for _, state := range g.states {
		if state.Anomaly {
			activeAnomalies++
		}
	}

	g.mu.RUnlock()

	now := time.Now()

	return Status{
		Name:              "Signal Grove",
		Version:           version,
		StartedAt:         g.startedAt.UTC(),
		UptimeSeconds:     int64(now.Sub(g.startedAt).Seconds()),
		Nodes:             nodes,
		Signals:           signals,
		Events:            events,
		ActiveAnomalies:   activeAnomalies,
		TotalReceived:     g.totalReceived.Load(),
		TotalAnomalies:    g.totalAnomalies.Load(),
		RejectedEvents:    g.rejected.Load(),
		HistoryLimit:      g.historyLimit,
		BaselineWindow:    g.window,
		MinimumSamples:    g.minSamples,
		AnomalyZScore:     g.threshold,
		AbsoluteTolerance: g.absoluteTolerance,
		RelativeTolerance: g.relativeTolerance,
		MaximumEventAge:   g.maxAge.String(),
		CurrentTime:       now.UTC(),
	}
}

func (g *Grove) Prune() int {
	if g.maxAge <= 0 {
		return 0
	}

	cutoff := time.Now().Add(-g.maxAge)

	g.mu.Lock()
	defer g.mu.Unlock()

	removed := 0
	filteredEvents := g.events[:0]

	for _, event := range g.events {
		if event.Timestamp.Before(cutoff) {
			removed++
			continue
		}

		filteredEvents = append(filteredEvents, event)
	}

	g.events = filteredEvents

	for key, history := range g.histories {
		filtered := history[:0]

		for _, sample := range history {
			if !sample.Timestamp.Before(cutoff) {
				filtered = append(filtered, sample)
			}
		}

		if len(filtered) == 0 {
			delete(g.histories, key)
			continue
		}

		if len(filtered) > g.window {
			filtered = filtered[len(filtered)-g.window:]
		}

		g.histories[key] = filtered
	}

	for key, state := range g.states {
		history, exists := g.histories[key]

		if !exists || len(history) == 0 {
			if state.LastUpdated.Before(cutoff) {
				delete(g.states, key)

				if node, ok := g.nodes[state.Node]; ok {
					delete(node.Signals, state.Signal)
				}
			}

			continue
		}

		mean, stdDev := calculateStats(history)

		state.Mean = mean
		state.StdDev = stdDev
		state.Samples = len(history)

		g.states[key] = state

		if node, ok := g.nodes[state.Node]; ok {
			node.Signals[state.Signal] = state
		}
	}

	for nodeName, node := range g.nodes {
		var latest time.Time

		for signalName := range node.Signals {
			key := signalKey(nodeName, signalName)
			currentState, exists := g.states[key]

			if !exists {
				delete(node.Signals, signalName)
				continue
			}

			node.Signals[signalName] = currentState

			if currentState.LastUpdated.After(latest) {
				latest = currentState.LastUpdated
			}
		}

		g.recalculateNodeAnomalies(node)

		if len(node.Signals) == 0 {
			if node.LastSeen.Before(cutoff) {
				delete(g.nodes, nodeName)
			}

			continue
		}

		if !latest.IsZero() {
			node.LastSeen = latest
		}
	}

	return removed
}

type Server struct {
	grove *Grove
	mux   *http.ServeMux
}

func NewServer(grove *Grove) *Server {
	server := &Server{
		grove: grove,
		mux:   http.NewServeMux(),
	}

	server.routes()

	return server
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleRoot)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/events", s.handleEvents)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/events", s.handleAPIEvents)
	s.mux.HandleFunc("/api/anomalies", s.handleAnomalies)
	s.mux.HandleFunc("/api/nodes", s.handleNodes)
	s.mux.HandleFunc("/api/signals", s.handleSignals)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	s.mux.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)

	if err := encoder.Encode(value); err != nil {
		log.Printf("response encoding error: %v", err)
	}
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)

	writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{
		Error: "method not allowed",
	})
}

func parseLimit(
	r *http.Request,
	defaultValue,
	maximum int,
) (int, error) {
	raw := r.URL.Query().Get("limit")

	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(raw)

	if err != nil {
		return 0, errors.New("limit must be an integer")
	}

	if value < 1 {
		return 0, errors.New("limit must be greater than zero")
	}

	if value > maximum {
		value = maximum
	}

	return value, nil
}

func (s *Server) handleRoot(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: "not found",
		})
		return
	}

	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":        "Signal Grove",
		"version":     version,
		"description": "Real-time signal monitoring and statistical anomaly detection engine",
		"status":      "running",
		"features": []string{
			"rolling statistical baselines",
			"Z-score anomaly detection",
			"zero-variance tolerance handling",
			"anomaly-resistant baseline learning",
			"bounded in-memory event history",
			"automatic age-based event pruning",
			"node and signal state tracking",
			"JSON HTTP API",
			"terminal monitoring dashboard",
		},
		"endpoints": []string{
			"POST /events",
			"GET /health",
			"GET /api/status",
			"GET /api/events",
			"GET /api/anomalies",
			"GET /api/nodes",
			"GET /api/signals",
		},
	})
}

func (s *Server) handleHealth(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	status := s.grove.Status()

	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "healthy",
		"service":          "Signal Grove",
		"version":          version,
		"uptime_seconds":   status.UptimeSeconds,
		"nodes":            status.Nodes,
		"signals":          status.Signals,
		"active_anomalies": status.ActiveAnomalies,
		"time":             time.Now().UTC(),
	})
}

func (s *Server) handleEvents(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		maxRequestBody,
	)
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var incoming IncomingEvent

	if err := decoder.Decode(&incoming); err != nil {
		s.grove.rejected.Add(1)

		var maxBytesError *http.MaxBytesError

		if errors.As(err, &maxBytesError) {
			writeJSON(
				w,
				http.StatusRequestEntityTooLarge,
				ErrorResponse{
					Error: "request body too large",
				},
			)
			return
		}

		writeJSON(
			w,
			http.StatusBadRequest,
			ErrorResponse{
				Error: "invalid JSON: " + err.Error(),
			},
		)
		return
	}

	var extra any

	if err := decoder.Decode(&extra); err != io.EOF {
		s.grove.rejected.Add(1)

		writeJSON(
			w,
			http.StatusBadRequest,
			ErrorResponse{
				Error: "request body must contain exactly one JSON object",
			},
		)
		return
	}

	event, err := s.grove.Add(incoming)

	if err != nil {
		writeJSON(
			w,
			http.StatusBadRequest,
			ErrorResponse{
				Error: err.Error(),
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		event,
	)
}

func (s *Server) handleStatus(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		s.grove.Status(),
	)
}

func (s *Server) handleAPIEvents(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	limit, err := parseLimit(
		r,
		100,
		1000,
	)

	if err != nil {
		writeJSON(
			w,
			http.StatusBadRequest,
			ErrorResponse{
				Error: err.Error(),
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"events": s.grove.Events(limit),
			"limit":  limit,
		},
	)
}

func (s *Server) handleAnomalies(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	limit, err := parseLimit(
		r,
		100,
		1000,
	)

	if err != nil {
		writeJSON(
			w,
			http.StatusBadRequest,
			ErrorResponse{
				Error: err.Error(),
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"anomalies": s.grove.Anomalies(limit),
			"limit":     limit,
		},
	)
}

func (s *Server) handleNodes(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	nodes := s.grove.Nodes()

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"nodes": nodes,
			"count": len(nodes),
		},
	)
}

func (s *Server) handleSignals(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	signals := s.grove.Signals()

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"signals": signals,
			"count":   len(signals),
		},
	)
}

func initializeScreen() {
	fmt.Print("\033[2J\033[H")
}

func resetCursor() {
	fmt.Print("\033[H")
}

func clearToEndOfScreen() {
	fmt.Print("\033[J")
}

func formatAge(timestamp time.Time) string {
	if timestamp.IsZero() {
		return "-"
	}

	duration := time.Since(timestamp)

	if duration < 0 {
		duration = 0
	}

	if duration < time.Second {
		return "<1s"
	}

	if duration < time.Minute {
		return fmt.Sprintf("%ds", int(duration.Seconds()))
	}

	if duration < time.Hour {
		return fmt.Sprintf("%dm", int(duration.Minutes()))
	}

	if duration < 24*time.Hour {
		return fmt.Sprintf("%dh", int(duration.Hours()))
	}

	return fmt.Sprintf("%dd", int(duration.Hours()/24))
}

func formatUptime(seconds int64) string {
	if seconds < 0 {
		seconds = 0
	}

	duration := time.Duration(seconds) * time.Second

	days := duration / (24 * time.Hour)
	duration %= 24 * time.Hour

	hours := duration / time.Hour
	duration %= time.Hour

	minutes := duration / time.Minute
	duration %= time.Minute

	secs := duration / time.Second

	if days > 0 {
		return fmt.Sprintf(
			"%dd %02dh %02dm %02ds",
			days,
			hours,
			minutes,
			secs,
		)
	}

	if hours > 0 {
		return fmt.Sprintf(
			"%02dh %02dm %02ds",
			hours,
			minutes,
			secs,
		)
	}

	if minutes > 0 {
		return fmt.Sprintf(
			"%02dm %02ds",
			minutes,
			secs,
		)
	}

	return fmt.Sprintf("%ds", secs)
}

func stateLabel(anomaly bool) string {
	if anomaly {
		return "ANOMALY"
	}

	return "NORMAL"
}

func learnedLabel(learned bool) string {
	if learned {
		return "YES"
	}

	return "NO"
}

func truncate(value string, maximum int) string {
	runes := []rune(value)

	if len(runes) <= maximum {
		return value
	}

	if maximum <= 0 {
		return ""
	}

	if maximum <= 3 {
		return string(runes[:maximum])
	}

	return string(runes[:maximum-3]) + "..."
}

func formatZScore(value *float64) string {
	if value == nil {
		return "-"
	}

	return fmt.Sprintf("%.2f", *value)
}

func renderDashboard(
	grove *Grove,
	addr string,
) {
	status := grove.Status()
	signals := grove.Signals()
	anomalies := grove.Anomalies(6)

	sort.Slice(signals, func(i, j int) bool {
		if signals[i].Anomaly != signals[j].Anomaly {
			return signals[i].Anomaly
		}

		if signals[i].Node == signals[j].Node {
			return signals[i].Signal < signals[j].Signal
		}

		return signals[i].Node < signals[j].Node
	})

	resetCursor()

	fmt.Println("SIGNAL GROVE")
	fmt.Println("Real-Time Signal Monitoring and Anomaly Detection Engine")
	fmt.Println(strings.Repeat("-", 92))

	fmt.Printf(
		"Version %-8s  Listen %-18s  Uptime %-18s\n",
		status.Version,
		addr,
		formatUptime(status.UptimeSeconds),
	)

	fmt.Printf(
		"Nodes   %-8d  Signals %-17d  Active anomalies %-8d\n",
		status.Nodes,
		status.Signals,
		status.ActiveAnomalies,
	)

	fmt.Printf(
		"Events  %-8d  Received %-16d  Detected anomalies %-6d\n",
		status.Events,
		status.TotalReceived,
		status.TotalAnomalies,
	)

	fmt.Printf(
		"Rejected %-7d  History %-17s  Retention %-14s\n",
		status.RejectedEvents,
		fmt.Sprintf("%d/%d", status.Events, status.HistoryLimit),
		status.MaximumEventAge,
	)

	fmt.Printf(
		"Window  %-8d  Minimum samples %-9d  Threshold %.2f sigma\n",
		status.BaselineWindow,
		status.MinimumSamples,
		status.AnomalyZScore,
	)

	fmt.Printf(
		"Zero-variance tolerance: absolute %.6f, relative %.4f\n",
		status.AbsoluteTolerance,
		status.RelativeTolerance,
	)

	fmt.Println(strings.Repeat("-", 92))

	if len(signals) == 0 {
		fmt.Println("SIGNAL STATE")
		fmt.Println("No signals have been received yet.")
		fmt.Println()
		fmt.Println("POST JSON events to /events to begin learning per-node, per-signal baselines.")
		fmt.Println("Anomaly detection starts after the minimum baseline sample count is reached.")
		fmt.Println("Detected anomalies are retained but are not learned into the baseline.")
		fmt.Println()
		fmt.Println("Press Ctrl-C to stop Signal Grove.")
		clearToEndOfScreen()
		return
	}

	fmt.Println("SIGNAL STATE")

	fmt.Printf(
		"%-14s %-18s %9s %9s %7s %4s %6s %8s %7s\n",
		"NODE",
		"SIGNAL",
		"VALUE",
		"MEAN",
		"Z",
		"N",
		"LEARN",
		"STATE",
		"AGE",
	)

	fmt.Println(strings.Repeat("-", 92))

	displayCount := len(signals)

	if displayCount > 16 {
		displayCount = 16
	}

	for i := 0; i < displayCount; i++ {
		state := signals[i]

		fmt.Printf(
			"%-14s %-18s %9.3f %9.3f %7s %4d %6s %8s %7s\n",
			truncate(state.Node, 14),
			truncate(state.Signal, 18),
			state.Value,
			state.Mean,
			formatZScore(state.ZScore),
			state.Samples,
			learnedLabel(state.Learned),
			stateLabel(state.Anomaly),
			formatAge(state.LastUpdated),
		)
	}

	if len(signals) > displayCount {
		fmt.Printf(
			"%d additional signals are tracked but not shown.\n",
			len(signals)-displayCount,
		)
	}

	fmt.Println()
	fmt.Println("RECENT ANOMALIES")

	if len(anomalies) == 0 {
		fmt.Println("No anomalies in retained event history.")
	} else {
		for _, event := range anomalies {
			fmt.Printf(
				"#%-5d %-14s %-18s value=%9.3f mean=%9.3f z=%7s age=%s\n",
				event.ID,
				truncate(event.Node, 14),
				truncate(event.Signal, 18),
				event.Value,
				event.Mean,
				formatZScore(event.ZScore),
				formatAge(event.Timestamp),
			)
		}
	}

	fmt.Println()
	fmt.Println("Normal observations update the rolling baseline. Anomalies do not alter it.")
	fmt.Println("Zero-variance baselines use configured absolute and relative tolerances.")
	fmt.Println("Press Ctrl-C to stop Signal Grove.")

	clearToEndOfScreen()
}

func runDashboard(
	ctx context.Context,
	grove *Grove,
	addr string,
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	initializeScreen()
	renderDashboard(grove, addr)

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			renderDashboard(grove, addr)
		}
	}
}

func runPruner(
	ctx context.Context,
	grove *Grove,
) {
	interval := time.Minute

	if grove.maxAge > 0 &&
		grove.maxAge < interval {
		interval = grove.maxAge / 2

		if interval < time.Second {
			interval = time.Second
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			grove.Prune()
		}
	}
}

func parseConfig() Config {
	var cfg Config

	flag.StringVar(
		&cfg.Addr,
		"addr",
		defaultAddr,
		"HTTP listen address",
	)

	flag.IntVar(
		&cfg.HistoryLimit,
		"history",
		defaultHistory,
		"maximum number of stored events",
	)

	flag.IntVar(
		&cfg.Window,
		"window",
		defaultWindow,
		"rolling baseline sample window",
	)

	flag.Float64Var(
		&cfg.Threshold,
		"threshold",
		defaultThreshold,
		"anomaly Z-score threshold",
	)

	flag.IntVar(
		&cfg.MinSamples,
		"min-samples",
		defaultMinSamples,
		"minimum baseline samples before anomaly detection",
	)

	flag.Float64Var(
		&cfg.AbsoluteTolerance,
		"absolute-tolerance",
		defaultAbsoluteTolerance,
		"absolute tolerance for zero-variance baselines",
	)

	flag.Float64Var(
		&cfg.RelativeTolerance,
		"relative-tolerance",
		defaultRelativeTolerance,
		"relative tolerance for zero-variance baselines",
	)

	flag.DurationVar(
		&cfg.MaxAge,
		"max-age",
		defaultMaxAge,
		"maximum stored event age",
	)

	flag.BoolVar(
		&cfg.Dashboard,
		"dashboard",
		true,
		"enable terminal dashboard",
	)

	flag.DurationVar(
		&cfg.DashboardRate,
		"dashboard-rate",
		2*time.Second,
		"terminal dashboard refresh interval",
	)

	flag.Parse()

	return cfg
}

func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Addr) == "" {
		return errors.New(
			"listen address cannot be empty",
		)
	}

	if cfg.HistoryLimit < 1 {
		return errors.New(
			"history must be greater than zero",
		)
	}

	if cfg.Window < 2 {
		return errors.New(
			"window must be at least 2",
		)
	}

	if cfg.MinSamples < 2 {
		return errors.New(
			"min-samples must be at least 2",
		)
	}

	if cfg.MinSamples > cfg.Window {
		return errors.New(
			"min-samples cannot exceed window",
		)
	}

	if math.IsNaN(cfg.Threshold) ||
		math.IsInf(cfg.Threshold, 0) ||
		cfg.Threshold <= 0 {
		return errors.New(
			"threshold must be a finite number greater than zero",
		)
	}

	if math.IsNaN(cfg.AbsoluteTolerance) ||
		math.IsInf(cfg.AbsoluteTolerance, 0) ||
		cfg.AbsoluteTolerance < 0 {
		return errors.New(
			"absolute-tolerance must be a finite non-negative number",
		)
	}

	if math.IsNaN(cfg.RelativeTolerance) ||
		math.IsInf(cfg.RelativeTolerance, 0) ||
		cfg.RelativeTolerance < 0 {
		return errors.New(
			"relative-tolerance must be a finite non-negative number",
		)
	}

	if cfg.AbsoluteTolerance == 0 &&
		cfg.RelativeTolerance == 0 {
		return errors.New(
			"at least one zero-variance tolerance must be greater than zero",
		)
	}

	if cfg.MaxAge <= 0 {
		return errors.New(
			"max-age must be greater than zero",
		)
	}

	if cfg.DashboardRate < 250*time.Millisecond {
		return errors.New(
			"dashboard-rate must be at least 250ms",
		)
	}

	return nil
}

func printStartup(cfg Config) {
	fmt.Println("Signal Grove")
	fmt.Println("Real-Time Signal Monitoring and Anomaly Detection Engine")
	fmt.Println()

	fmt.Printf("Version:             %s\n", version)
	fmt.Printf("Listen address:      %s\n", cfg.Addr)
	fmt.Printf("Event history limit: %d\n", cfg.HistoryLimit)
	fmt.Printf("Baseline window:     %d samples\n", cfg.Window)
	fmt.Printf("Minimum samples:     %d samples\n", cfg.MinSamples)
	fmt.Printf("Z-score threshold:   %.2f sigma\n", cfg.Threshold)
	fmt.Printf("Absolute tolerance:  %.6f\n", cfg.AbsoluteTolerance)
	fmt.Printf("Relative tolerance:  %.4f\n", cfg.RelativeTolerance)
	fmt.Printf("Maximum event age:   %s\n", cfg.MaxAge)
	fmt.Println()
	fmt.Println("Signal Grove is ready to receive events.")
	fmt.Println("POST JSON events to /events.")
	fmt.Println("Press Ctrl-C to stop.")
}

func printStartupError(cfg Config, err error) {
	fmt.Fprintln(os.Stderr, "Signal Grove")
	fmt.Fprintln(os.Stderr, "Startup failed.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Version: %s\n", version)
	fmt.Fprintf(os.Stderr, "Address: %s\n", cfg.Addr)
	fmt.Fprintf(os.Stderr, "Error:   %v\n", err)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Signal Grove could not start its HTTP server.")
}

func printShutdown(status Status) {
	fmt.Println("Signal Grove stopped.")
	fmt.Printf("Total events received:    %d\n", status.TotalReceived)
	fmt.Printf("Total anomalies detected: %d\n", status.TotalAnomalies)
	fmt.Printf("Rejected events:          %d\n", status.RejectedEvents)
	fmt.Printf("Events retained:          %d\n", status.Events)
	fmt.Printf("Nodes tracked:            %d\n", status.Nodes)
	fmt.Printf("Signals tracked:          %d\n", status.Signals)
	fmt.Printf("Active anomalies:         %d\n", status.ActiveAnomalies)
}

func main() {
	cfg := parseConfig()

	if err := validateConfig(cfg); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"Configuration error: %v\n",
			err,
		)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", cfg.Addr)

	if err != nil {
		printStartupError(cfg, err)
		os.Exit(1)
	}

	grove := NewGrove(cfg)
	handler := NewServer(grove)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	go runPruner(
		ctx,
		grove,
	)

	serverErrors := make(chan error, 1)

	go func() {
		err := server.Serve(listener)

		if err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	if cfg.Dashboard {
		go runDashboard(
			ctx,
			grove,
			cfg.Addr,
			cfg.DashboardRate,
		)
	} else {
		printStartup(cfg)
	}

	var serverErr error

	select {
	case <-ctx.Done():

	case serverErr = <-serverErrors:
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	shutdownErr := server.Shutdown(shutdownCtx)

	if cfg.Dashboard {
		fmt.Print("\033[H\033[J")
	}

	if serverErr != nil {
		fmt.Fprintln(os.Stderr, "Signal Grove")
		fmt.Fprintln(os.Stderr, "Server stopped unexpectedly.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Error: %v\n", serverErr)

		if shutdownErr != nil {
			fmt.Fprintf(
				os.Stderr,
				"Shutdown error: %v\n",
				shutdownErr,
			)
		}

		os.Exit(1)
	}

	if shutdownErr != nil {
		fmt.Fprintf(
			os.Stderr,
			"Shutdown error: %v\n",
			shutdownErr,
		)
	}

	printShutdown(grove.Status())
}
