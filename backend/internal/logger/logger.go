package logger

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/database"
)

type SiemForwarder interface {
	Forward(evt *database.Event)
}

type EventLogger struct {
	db        *database.DB
	queue     chan *database.Event
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	forwarder SiemForwarder
}

func NewEventLogger(db *database.DB, queueSize int, sf SiemForwarder) *EventLogger {
	ctx, cancel := context.WithCancel(context.Background())
	el := &EventLogger{
		db:        db,
		queue:     make(chan *database.Event, queueSize),
		ctx:       ctx,
		cancel:    cancel,
		forwarder: sf,
	}
	el.wg.Add(1)
	go el.run()
	return el
}

func (el *EventLogger) Log(evt map[string]interface{}) {
	service, _ := evt["service"].(string)
	eventType, _ := evt["event_type"].(string)

	var srcIP *string
	if val, ok := evt["src_ip"].(string); ok && val != "" {
		srcIP = &val
	}

	var srcPort *int
	if val, ok := evt["src_port"].(int); ok {
		srcPort = &val
	} else if valFloat, ok := evt["src_port"].(float64); ok {
		iVal := int(valFloat)
		srcPort = &iVal
	}

	var summary *string
	if val, ok := evt["summary"].(string); ok && val != "" {
		summary = &val
	}

	detailsMap := make(map[string]interface{})
	for k, v := range evt {
		if k != "service" && k != "event_type" && k != "src_ip" && k != "src_port" && k != "summary" && k != "timestamp" {
			detailsMap[k] = v
		}
	}

	var details json.RawMessage
	if len(detailsMap) > 0 {
		if data, err := json.Marshal(detailsMap); err == nil {
			details = data
		}
	}

	dbEvt := &database.Event{
		Timestamp: time.Now().UTC(),
		Service:   service,
		EventType: eventType,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		Summary:   summary,
		Details:   details,
	}

	// Also print to stdout matching python log statement
	ipStr := "N/A"
	if srcIP != nil {
		ipStr = *srcIP
	}
	sumStr := ""
	if summary != nil {
		sumStr = *summary
	}
	log.Printf("[EVENT] service=%s event_type=%s src_ip=%s %s\n", service, eventType, ipStr, sumStr)

	select {
	case el.queue <- dbEvt:
	default:
		log.Println("Event logger queue full, dropping event:", service, eventType)
	}
}

func (el *EventLogger) run() {
	defer el.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var batch []*database.Event
	maxBatchSize := 100

	flush := func() {
		if len(batch) == 0 {
			return
		}
		flushCtx := context.Background()
		for _, evt := range batch {
			if err := el.db.InsertEvent(flushCtx, evt); err != nil {
				log.Println("Error inserting event into DB:", err)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case evt := <-el.queue:
			batch = append(batch, evt)
			if el.forwarder != nil {
				el.forwarder.Forward(evt)
			}
			if len(batch) >= maxBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-el.ctx.Done():
			// Drain remaining events from queue before final flush
			for {
				select {
				case evt := <-el.queue:
					batch = append(batch, evt)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (el *EventLogger) Close() {
	el.cancel()
	el.wg.Wait()
}
