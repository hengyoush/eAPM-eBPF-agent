package agent

import (
	"bytes"
	"container/list"
	"eapm-ebpf/common"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/viper"
)

var LaunchEpochTime uint64

func SetupAgent() {
	InitReporter()

	LaunchEpochTime = GetMachineStartTimeNano()
	stopper := make(chan os.Signal, 1)
	connManager := InitConnManager()

	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Remove memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs agentObjects
	if err := loadAgentObjects(&objs, nil); err != nil {
		log.Println("loadAgentObjects:", err)
		return
	}

	defer objs.Close()

	links := attachBpfProgs(objs)

	for e := links.Front(); e != nil; e = e.Next() {
		if e.Value == nil {
			continue
		}
		if l, ok := e.Value.(link.Link); ok {
			defer func() {
				l.Close()
			}()
		}
	}
	// kernel >= 5.8
	dataReader, err := ringbuf.NewReader(objs.agentMaps.Rb)
	if err != nil {
		log.Println("new dataReader ringbuffer err:", err)
		return
	}
	defer dataReader.Close()

	connEvtReader, err := ringbuf.NewReader(objs.agentMaps.ConnEvtRb)
	if err != nil {
		log.Println("new connEvtReader ringbuffer err:", err)
		return
	}
	defer connEvtReader.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	stop := false
	go func() {
		<-stopper
		log.Println("stop!")
		if err := dataReader.Close(); err != nil {
			log.Fatalf("closing dataReader error: %s", err)
		}
		if err := connEvtReader.Close(); err != nil {
			log.Fatalf("closing connEvtReader error: %s", err)
		}
		stop = true
	}()

	log.Println("Waiting for events..")

	// https://github.com/cilium/ebpf/blob/main/examples/ringbuffer/ringbuffer.c
	go func() {
		for {
			record, err := dataReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("[dataReader] Received signal, exiting..")
					return
				}
				log.Printf("[dataReader] reading from reader: %s", err)
				continue
			}
			if err := handleKernEvt(record.RawSample, connManager); err != nil {
				log.Printf("[dataReader] handleKernEvt err: %s", err)
				continue
			}

		}
	}()

	go func() {
		for {
			record, err := connEvtReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("[connEvtReader] Received signal, exiting..")
					return
				}
				log.Printf("[connEvtReader] reading from reader: %s", err)
				continue
			}
			if err := handleConnEvt(record.RawSample, connManager); err != nil {
				log.Printf("[connEvtReader] handleKernEvt err: %s", err)
				continue
			}
		}
	}()

	for !stop {
		time.Sleep(time.Second * 1)
	}
	log.Println("Stopped")
	return
}
func handleConnEvt(record []byte, connManager *ConnManager) error {
	var event agentConnEvtT
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}
	TgidFd := uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd)
	conn := Connection4{
		localIp:    event.ConnInfo.Laddr.In4.SinAddr.S_addr,
		remoteIp:   event.ConnInfo.Raddr.In4.SinAddr.S_addr,
		localPort:  event.ConnInfo.Laddr.In4.SinPort,
		remotePort: event.ConnInfo.Raddr.In4.SinPort,
		protocol:   event.ConnInfo.Protocol,
		role:       event.ConnInfo.Role,
		tgidFd:     uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd),
	}

	if event.ConnType == agentConnTypeTKConnect {
		connManager.AddConnection4(TgidFd, &conn)
	} else if event.ConnType == agentConnTypeTKClose {
		go func() {
			time.Sleep(1 * time.Second)
			connManager.RemoveConnection4(TgidFd)
		}()
	} else if event.ConnType == agentConnTypeTKProtocolInfer {
		// 协议推断
		conn := connManager.findConnection4(TgidFd)
		if conn != nil {
			conn.protocol = event.ConnInfo.Protocol
		} else {
			return nil
		}
		if conn.protocol != agentTrafficProtocolTKProtocolUnknown {
			ReportDataEvents(conn.TempEvents, conn)
		}
		// 清空, 这里可能有race
		conn.TempEvents = conn.TempEvents[0:0]
	}
	direct := "=>"
	if event.ConnInfo.Role != agentEndpointRoleTKRoleClient {
		direct = "<="
	}
	eventType := "connect"
	if event.ConnType == agentConnTypeTKClose {
		eventType = "close"
	} else if event.ConnType == agentConnTypeTKProtocolInfer {
		eventType = "infer"
	}
	event.Ts += LaunchEpochTime
	if viper.GetBool(common.ConsoleOutputVarName) {
		log.Printf("[conn][tgid=%d fd=%d] %s:%d %s %s:%d | type: %s, protocol: %d, \n", event.ConnInfo.ConnId.Upid.Pid, event.ConnInfo.ConnId.Fd, intToIP(conn.localIp), conn.localPort, direct, intToIP(conn.remoteIp), conn.remotePort, eventType, conn.protocol)
	}

	go func() {
		ReportConnEvent(&event)
	}()
	return nil
}
func handleKernEvt(record []byte, connManager *ConnManager) error {
	var event agentKernEvt
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}
	tgidFd := event.ConnIdS.TgidFd
	conn := connManager.findConnection4(tgidFd)
	event.Ts += LaunchEpochTime
	if conn != nil {
		direct := "=>"
		if event.ConnIdS.Direct == agentTrafficDirectionTKIngress {
			direct = "<="
		}
		if viper.GetBool(common.ConsoleOutputVarName) {
			log.Printf("[data][tgid_fd=%d][func=%s][%s] %s:%d %s %s:%d | %d:%d\n", tgidFd, int8ToStr(event.FuncName[:]), StepAsString(Step(event.Step)), intToIP(conn.localIp), conn.localPort, direct, intToIP(conn.remoteIp), conn.remotePort, event.Seq, event.Len)
		}

	} else {
		log.Println("failed to retrieve conn from connManager")
	}
	if event.Len > 0 && conn != nil && conn.protocol != agentTrafficProtocolTKProtocolUnknown {
		go func() {
			if conn != nil {
				if conn.protocol == agentTrafficProtocolTKProtocolUnset {
					conn.AddEvent(&event)
				} else if conn.protocol != agentTrafficProtocolTKProtocolUnknown {
					ReportDataEvent(&event, conn)
				}
			}
		}()
	}
	return nil
}

func attachBpfProgs(objs agentObjects) *list.List {
	linkList := list.New()

	l := kprobe("__sys_accept4", objs.agentPrograms.Accept4Entry)
	linkList.PushBack(l)
	l = kretprobe("__sys_accept4", objs.agentPrograms.SysAccept4Ret)
	linkList.PushBack(l)

	l = kretprobe("sock_alloc", objs.agentPrograms.SockAllocRet)
	linkList.PushBack(l)

	l = kretprobe("__sys_connect", objs.agentPrograms.SysConnectRet)
	linkList.PushBack(l)
	l = kprobe("__sys_connect", objs.agentPrograms.ConnectEntry)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_close", objs.agentPrograms.CloseEntry)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_close", objs.agentPrograms.SysCloseRet)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_write", objs.agentPrograms.WriteEnter)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_write", objs.agentPrograms.WriteReturn)
	linkList.PushBack(l)

	l = kprobe("__sys_sendto", objs.agentPrograms.SendtoEnter)
	linkList.PushBack(l)
	l = kretprobe("__sys_sendto", objs.agentPrograms.SendtoReturn)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_read", objs.agentPrograms.ReadEnter)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_read", objs.agentPrograms.ReadReturn)
	linkList.PushBack(l)

	l = kprobe("__sys_recvfrom", objs.agentPrograms.RecvfromEnter)
	linkList.PushBack(l)
	l = kretprobe("__sys_recvfrom", objs.agentPrograms.RecvfromReturn)
	linkList.PushBack(l)

	l = kprobe("security_socket_recvmsg", objs.agentPrograms.SecuritySocketRecvmsgEnter)
	linkList.PushBack(l)
	l = kprobe("security_socket_sendmsg", objs.agentPrograms.SecuritySocketSendmsgEnter)
	linkList.PushBack(l)

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: objs.agentPrograms.TcpDestroySock,
	})
	if err != nil {
		log.Fatal("tcp_destroy_sock failed: ", err)
	}
	linkList.PushBack(l)

	l = kprobe("ip_queue_xmit", objs.agentPrograms.IpQueueXmit)
	linkList.PushBack(l)
	l = kprobe("dev_queue_xmit", objs.agentPrograms.DevQueueXmit)
	linkList.PushBack(l)
	l = kprobe("dev_hard_start_xmit", objs.agentPrograms.DevHardStartXmit)
	linkList.PushBack(l)

	if l, err = kprobe2("ip_rcv_core", objs.agentPrograms.IpRcvCore); err != nil {
		l = kprobe("ip_rcv_core.isra.0", objs.agentPrograms.IpRcvCore)
	}
	linkList.PushBack(l)

	l = kprobe("tcp_v4_do_rcv", objs.agentPrograms.TcpV4DoRcv)
	linkList.PushBack(l)
	l = kprobe("__skb_datagram_iter", objs.agentPrograms.SkbCopyDatagramIter)
	linkList.PushBack(l)

	ifname := "eth0" // TODO
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	l, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.agentPrograms.XdpProxy,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	linkList.PushBack(l)
	return linkList
}

func kprobe(func_name string, prog *ebpf.Program) link.Link {
	if link, err := link.Kprobe(func_name, prog, nil); err != nil {
		log.Fatalf("kprobe failed: %s, %s", func_name, err)
		return nil
	} else {
		return link
	}
}

func kprobe2(func_name string, prog *ebpf.Program) (link.Link, error) {
	if link, err := link.Kprobe(func_name, prog, nil); err != nil {
		log.Fatalf("kprobe2 failed: %s, %s", func_name, err)
		return nil, err
	} else {
		return link, nil
	}
}

func kretprobe(func_name string, prog *ebpf.Program) link.Link {
	if link, err := link.Kretprobe(func_name, prog, nil); err != nil {
		log.Fatalf("kretprobe failed: %s, %s", func_name, err)
		return nil
	} else {
		return link
	}
}
