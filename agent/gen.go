package agent

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type kern_evt -type conn_evt_t -type conn_type_t -type endpoint_role_t -type traffic_direction_t -type traffic_protocol_t -target amd64 agent ../pktlatency.bpf.c -- -I./ -I$OUTPUT -I../libbpf/include/uapi -I../vmlinux/x86/ -I/usr/local/include/glib-2.0 -I/usr/local/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/local/include -I/usr/include/mysql/
