package agent

import (
	"bytes"
	"eapm-ebpf/common"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/viper"
)

type Conn struct {
	SrcIP    uint32 `json:"srcIp"`
	SrcPort  uint16 `json:"srcPort"`
	DstIP    uint32 `json:"dstIp"`
	DstPort  uint16 `json:"dstPort"`
	Protocol uint32 `json:"protocol"`
	TgidFd   uint64 `json:"tgidFd"`
}

type ConnEvent struct {
	Conn      Conn   `json:"conn"`
	Timestamp uint64 `json:"timestamp"`
	Type      int    `json:"type"`
	Tags      string `json:"tags"`
}

type DataEvent struct {
	Conn      Conn   `json:"conn"`
	Seq       uint64 `json:"seq"`
	Len       uint32 `json:"len"`
	Source    uint32 `json:"source"`
	Direct    uint32 `json:"direct"`
	Timestamp uint64 `json:"timestamp"`
	TraceId   string `json:"traceId"`
	SpanId    string `json:"spanId"`
}

var httpClient *http.Client = &http.Client{}
var connEventEndpoint string
var dataEventEndpoint string

func InitReporter() {
	connEventEndpoint = "http://" + viper.GetString(common.CollectorAddrVarName) + "/event-collector/conn-event"
	dataEventEndpoint = "http://" + viper.GetString(common.CollectorAddrVarName) + "/event-collector/data-event"
}

type DirectEnum uint32

const (
	toDst DirectEnum = 0
	toSrc DirectEnum = 1
)

type Step uint32

const (
	Start Step = iota
	SyscallOut
	TcpOut
	IpOut
	QdiscOut
	DevOut
	NicOut
	NicIn
	DevIn
	IpIn
	TcpIn
	UserCopy
	SyscallIn
)

func StepAsString(s Step) string {
	switch s {
	case Start:
		return "start"
	case SyscallOut:
		return "SYSCALL_OUT"
	case TcpOut:
		return "TCP_OUT"
	case IpOut:
		return "IP_OUT"
	case QdiscOut:
		return "QDISC_OUT"
	case DevOut:
		return "DEV_OUT"
	case NicOut:
		return "NIC_OUT"
	case NicIn:
		return "NIC_IN"
	case DevIn:
		return "DEV_IN"
	case IpIn:
		return "IP_IN"
	case TcpIn:
		return "TCP_IN"
	case UserCopy:
		return "USER_COPY"
	case SyscallIn:
		return "SYSCALL_IN"
	default:
		return fmt.Sprintf("Unknown step: %d", s)
	}
}

func ReportDataEvents(event []*agentKernEvt, conn *Connection4) error {
	for _, e := range event {
		err := ReportDataEvent(e, conn)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReportDataEvent(event *agentKernEvt, conn *Connection4) error {
	if viper.GetBool(common.LocalModeVarName) {
		return nil
	}
	var dataEvent DataEvent
	var direct uint32
	if conn.role == agentEndpointRoleTKRoleClient {
		if uint32(event.ConnIdS.Direct) == uint32(agentTrafficDirectionTKIngress) {
			direct = uint32(toSrc)
		} else {
			direct = uint32(toDst)
		}
		dataEvent = DataEvent{
			Conn: Conn{
				SrcIP:    conn.localIp,
				SrcPort:  conn.localPort,
				DstIP:    conn.remoteIp,
				DstPort:  conn.remotePort,
				Protocol: 0,
				TgidFd:   event.ConnIdS.TgidFd,
			},
			Seq:       event.Seq,
			Len:       event.Len,
			Direct:    direct,
			Timestamp: event.Ts,
			Source:    event.Step,
		}
	} else {
		if uint32(event.ConnIdS.Direct) == uint32(agentTrafficDirectionTKIngress) {
			direct = uint32(toDst)
		} else {
			direct = uint32(toSrc)
		}
		dataEvent = DataEvent{
			Conn: Conn{
				DstIP:    conn.localIp,
				DstPort:  conn.localPort,
				SrcIP:    conn.remoteIp,
				SrcPort:  conn.remotePort,
				Protocol: 0,
				TgidFd:   event.ConnIdS.TgidFd,
			},
			Seq:       event.Seq,
			Len:       event.Len,
			Direct:    direct,
			Timestamp: event.Ts,
			Source:    event.Step,
		}
	}
	jsonData, err := json.Marshal(dataEvent)
	if err != nil {
		return err
	}
	fmt.Println(string(jsonData))
	// 构造 HTTP 请求
	req, err := http.NewRequest("POST", dataEventEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送 HTTP 请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Failed to send request:", err)
		return err
	}
	defer resp.Body.Close()

	// 打印响应状态码
	if viper.GetBool(common.VerboseVarName) {
		fmt.Println("Response Status:", resp.Status)
	}

	return nil
}

func ReportConnEvent(event *agentConnEvtT) error {
	if viper.GetBool(common.LocalModeVarName) {
		return nil
	}
	var connEvent ConnEvent
	if event.ConnInfo.Role == agentEndpointRoleTKRoleClient {
		connEvent = ConnEvent{
			Conn: Conn{
				SrcIP:    event.ConnInfo.Laddr.In4.SinAddr.S_addr,
				SrcPort:  event.ConnInfo.Laddr.In4.SinPort,
				DstIP:    event.ConnInfo.Raddr.In4.SinAddr.S_addr,
				DstPort:  event.ConnInfo.Raddr.In4.SinPort,
				Protocol: 0,
				TgidFd:   uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd),
			},
			Timestamp: event.Ts,
			Type:      int(event.ConnType),
		}
	} else {
		connEvent = ConnEvent{
			Conn: Conn{
				SrcIP:    event.ConnInfo.Raddr.In4.SinAddr.S_addr,
				SrcPort:  event.ConnInfo.Raddr.In4.SinPort,
				DstIP:    event.ConnInfo.Laddr.In4.SinAddr.S_addr,
				DstPort:  event.ConnInfo.Laddr.In4.SinPort,
				Protocol: 0,
				TgidFd:   uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd),
			},
			Timestamp: event.Ts,
			Type:      int(event.ConnType),
		}
	}
	jsonData, err := json.Marshal(connEvent)
	if err != nil {
		return err
	}
	fmt.Println(string(jsonData))
	// 构造 HTTP 请求
	req, err := http.NewRequest("POST", connEventEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送 HTTP 请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Failed to send request:", err)
		return err
	}
	defer resp.Body.Close()

	// 打印响应状态码
	if viper.GetBool(common.VerboseVarName) {
		fmt.Println("Response Status:", resp.Status)
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Println("Body: ", string(bodyBytes))
	}

	return nil
}
