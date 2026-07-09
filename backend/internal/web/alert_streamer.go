package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/database"
)

type AlertStreamer struct {
	db        *database.DB
	clients   map[chan string]bool
	mu        sync.Mutex
	lastID    int
	started   bool
	startOnce sync.Once
}

func NewAlertStreamer(db *database.DB) *AlertStreamer {
	return &AlertStreamer{
		db:      db,
		clients: make(map[chan string]bool),
	}
}

func (as *AlertStreamer) Start(ctx context.Context) {
	as.startOnce.Do(func() {
		// Initialize lastID
		var maxID int
		err := as.db.Pool.QueryRow(ctx, "SELECT COALESCE(MAX(id), 0) FROM events").Scan(&maxID)
		if err == nil {
			as.lastID = maxID
		} else {
			log.Println("AlertStreamer init error:", err)
		}
		as.started = true
		go as.pollEvents(ctx)
	})
}

type AlertPayload struct {
	Type      string `json:"type"`
	SrcIP     string `json:"src_ip"`
	Count     int    `json:"count,omitempty"`
	EventType string `json:"event_type,omitempty"`
	Service   string `json:"service,omitempty"`
	Summary   string `json:"summary"`
}

type AlertBroadcast struct {
	Alerts []AlertPayload `json:"alerts"`
}

func (as *AlertStreamer) pollEvents(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			as.mu.Lock()
			hasClients := len(as.clients) > 0
			as.mu.Unlock()

			if !hasClients {
				continue
			}

			// Fetch new events
			rows, err := as.db.Pool.Query(ctx,
				"SELECT id, timestamp, service, event_type, src_ip, summary FROM events WHERE id > $1 ORDER BY id ASC",
				as.lastID,
			)
			if err != nil {
				log.Println("AlertStreamer query error:", err)
				continue
			}

			type TempEvent struct {
				ID        int
				Service   string
				EventType string
				SrcIP     string
				Summary   string
			}

			var fetched []TempEvent
			maxFetchedID := as.lastID

			for rows.Next() {
				var e TempEvent
				var t time.Time
				var srcIPNull, summaryNull *string
				if err := rows.Scan(&e.ID, &t, &e.Service, &e.EventType, &srcIPNull, &summaryNull); err == nil {
					if srcIPNull != nil {
						e.SrcIP = *srcIPNull
					}
					if summaryNull != nil {
						e.Summary = *summaryNull
					}
					fetched = append(fetched, e)
					if e.ID > maxFetchedID {
						maxFetchedID = e.ID
					}
				}
			}
			rows.Close()

			if len(fetched) == 0 {
				continue
			}

			as.lastID = maxFetchedID

			// Group by IP
			ipEvents := make(map[string][]TempEvent)
			for _, e := range fetched {
				if e.SrcIP != "" {
					ipEvents[e.SrcIP] = append(ipEvents[e.SrcIP], e)
				}
			}

			var alerts []AlertPayload
			for ip, evs := range ipEvents {
				count := len(evs)
				if count > 5 {
					alerts = append(alerts, AlertPayload{
						Type:    "aggregated",
						SrcIP:   ip,
						Count:   count,
						Summary: fmt.Sprintf("Yüksek yoğunluklu şüpheli aktivite (Port Tarama/Flood) tespit edildi: %d istek.", count),
					})
				} else {
					for _, e := range evs {
						sum := e.Summary
						if sum == "" {
							sum = fmt.Sprintf("%s üzerinde %s tespit edildi.", e.Service, e.EventType)
						}
						alerts = append(alerts, AlertPayload{
							Type:      "individual",
							SrcIP:     ip,
							EventType: e.EventType,
							Service:   e.Service,
							Summary:   sum,
						})
					}
				}
			}

			if len(alerts) > 0 {
				broadcast := AlertBroadcast{Alerts: alerts}
				bytes, err := json.Marshal(broadcast)
				if err == nil {
					as.Broadcast(string(bytes))
				}
			}
		}
	}
}

func (as *AlertStreamer) Broadcast(msg string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	for client := range as.clients {
		select {
		case client <- msg:
		default:
			// Client channel full, skip
		}
	}
}

func (as *AlertStreamer) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Encoding", "no") // Disable Nginx buffering

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	clientChan := make(chan string, 100)

	as.mu.Lock()
	as.clients[clientChan] = true
	as.mu.Unlock()

	defer func() {
		as.mu.Lock()
		delete(as.clients, clientChan)
		as.mu.Unlock()
	}()

	// Send initial ping to establish connection
	fmt.Fprintf(w, "data: %s\n\n", `{"type":"ping"}`)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-clientChan:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, "data: %s\n\n", `{"type":"ping"}`)
			flusher.Flush()
		}
	}
}
