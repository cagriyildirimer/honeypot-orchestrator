//go:build !linux || !cgo

package system

import "log"

type stubPacketMangler struct {
	queueNum      int
	activeProfile string
}

func newPacketManglerImpl(queueNum int) PacketMangler {
	return &stubPacketMangler{queueNum: queueNum, activeProfile: "linux_server"}
}

func (m *stubPacketMangler) Start() {
	log.Printf("PacketMangler stub started on queue %d (NFQUEUE is disabled on this platform/build).\n", m.queueNum)
}

func (m *stubPacketMangler) Stop() {
	log.Println("PacketMangler stub stopped.")
}

func (m *stubPacketMangler) SetProfile(profileName string) {
	log.Printf("PacketMangler stub profile updated to: %s\n", profileName)
	m.activeProfile = profileName
}
