//go:build linux

package system

import (
	"context"
	"log"
	"sync"

	"github.com/florianl/go-nfqueue"
	"golang.org/x/sys/unix"
)

type linuxPacketMangler struct {
	queueNum      int
	activeProfile string
	nfq           *nfqueue.Nfqueue
	running       bool
	mu            sync.Mutex
	cancel        context.CancelFunc
}

func newPacketManglerImpl(queueNum int) PacketMangler {
	return &linuxPacketMangler{
		queueNum:      queueNum,
		activeProfile: "linux_server",
	}
}

func (m *linuxPacketMangler) SetProfile(profileName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Printf("PacketMangler profile updated to: %s\n", profileName)
	m.activeProfile = profileName
}

func (m *linuxPacketMangler) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return
	}

	config := nfqueue.Config{
		NfQueue:      uint16(m.queueNum),
		MaxQueueLen:  100,
		MaxPacketLen: 0xFFFF,
		AfFamily:     unix.AF_INET,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nfq, err := nfqueue.Open(&config)
	if err != nil {
		log.Printf("PacketMangler failed to initialize NFQUEUE: %v\n", err)
		return
	}
	m.nfq = nfq

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.running = true

	fn := func(attr nfqueue.Attribute) int {
		if attr.PacketID != nil {
			// Accept all packets (NF_ACCEPT = 1)
			m.nfq.SetVerdict(*attr.PacketID, nfqueue.NfAccept)
		}
		return 0
	}

	errFn := func(err error) int {
		log.Printf("PacketMangler NFQUEUE error: %v\n", err)
		return 0
	}

	if err := m.nfq.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		log.Printf("PacketMangler NFQUEUE registration failed: %v\n", err)
		m.nfq.Close()
		m.running = false
		return
	}

	log.Printf("PacketMangler started on queue %d\n", m.queueNum)
}

func (m *linuxPacketMangler) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	m.running = false
	if m.cancel != nil {
		m.cancel()
	}
	if m.nfq != nil {
		m.nfq.Close()
	}
	log.Println("PacketMangler stopped.")
}
