package agent

type Connection4 struct {
	localIp    uint32
	remoteIp   uint32
	localPort  uint16
	remotePort uint16
	protocol   agentTrafficProtocolT
	role       agentEndpointRoleT
	tgidFd     uint64
	TempEvents []*agentKernEvt
}

type ConnManager struct {
	connMap map[uint64]*Connection4
}

func InitConnManager() *ConnManager {
	return &ConnManager{connMap: make(map[uint64]*Connection4)}
}

func (c *ConnManager) AddConnection4(TgidFd uint64, conn *Connection4) error {
	c.connMap[TgidFd] = conn
	return nil
}

func (c *ConnManager) RemoveConnection4(TgidFd uint64) {
	delete(c.connMap, TgidFd)
}

func (c *ConnManager) findConnection4(TgidFd uint64) *Connection4 {
	return c.connMap[TgidFd]
}

func (c *Connection4) AddEvent(e *agentKernEvt) {
	c.TempEvents = append(c.TempEvents, e)
}
