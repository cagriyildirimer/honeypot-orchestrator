package system

type PacketMangler interface {
	Start()
	Stop()
	SetProfile(profileName string)
}

func NewPacketMangler(queueNum int) PacketMangler {
	return newPacketManglerImpl(queueNum)
}
