#ifndef __KPROBE_H__
#define __KPROBE_H__

#define PX_AF_UNKNOWN 0xff
#define MAX_MSG_SIZE 30720
#define EINPROGRESS 115

// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_endian.h>
// #include <linux/in.h>
// #include <linux/in6.h>
// #include <linux/socket.h>

enum step_t {
  start = 0,
  SYSCALL_OUT,
  TCP_OUT,
  IP_OUT,
  QDISC_OUT,
  DEV_OUT,
  NIC_OUT,
  NIC_IN,
  DEV_IN,
  IP_IN,
  TCP_IN,
  USER_COPY,
  SYSCALL_IN
};

enum traffic_protocol_t {
  kProtocolUnset = 0,
  kProtocolUnknown,
  kProtocolHTTP,
  kProtocolHTTP2,
  kProtocolMySQL,
  kProtocolCQL,
  kProtocolPGSQL,
  kProtocolDNS,
  kProtocolRedis,
  kProtocolNATS,
  kProtocolMongo,
  kProtocolKafka,
  kProtocolMux,
  kProtocolAMQP,
  kNumProtocols
};

enum endpoint_role_t {
  kRoleClient = 1 << 0,
  kRoleServer = 1 << 1,
  kRoleUnknown = 1 << 2,
};

enum source_function_t {
  kSourceFunctionUnknown,

  // For syscalls.
  kSyscallAccept,
  kSyscallConnect,
  kSyscallClose,
  kSyscallWrite,
  kSyscallRead,
  kSyscallSend,
  kSyscallRecv,
  kSyscallSendTo,
  kSyscallRecvFrom,
  kSyscallSendMsg,
  kSyscallRecvMsg,
  kSyscallSendMMsg,
  kSyscallRecvMMsg,
  kSyscallWriteV,
  kSyscallReadV,
  kSyscallSendfile,

  // For Go TLS libraries.
  kGoTLSConnWrite,
  kGoTLSConnRead,

  // For SSL libraries.
  kSSLWrite,
  kSSLRead,
};
enum message_type_t { kUnknown, kRequest, kResponse };

struct protocol_message_t {
  enum traffic_protocol_t protocol;
  enum message_type_t type;
};

enum traffic_direction_t {
  kEgress,
  kIngress,
};

enum conn_type_t {
  kConnect,
  kClose,
  kProtocolInfer,
};

struct sock_key {
	uint32_t sip;
	uint32_t dip;
	uint32_t sport;
	uint32_t dport;
	uint32_t family;
};

#define FUNC_NAME_LIMIT 16 
#define CMD_LEN 16 

// struct event {
// 	pid_t pid;
// 	uint32_t init_seq;
// 	uint32_t tcp_seq;
// 	struct sock_key *key;
// 	uint32_t cur_seq;
// 	uint32_t data_len;
// 	bool is_sample;
// 	__u64 ts;
// 	uint32_t inode;
// };


struct upid_t {
  union {
    uint32_t pid;
    uint32_t tgid;
  };
  uint64_t start_time_ticks;
};

struct conn_id_t {
  //  pid/tgid.
  struct upid_t upid;
  // The file descriptor to the opened network connection.
  int32_t fd;
  // Unique id of the conn_id (timestamp).
  uint64_t tsid;
};


struct conn_id_s_t {
	uint64_t tgid_fd;
	// 0-入向 1-出向
	enum traffic_direction_t direct;
};

struct kern_evt {
	char func_name[FUNC_NAME_LIMIT];
	uint64_t ts;
	uint64_t seq;
	uint32_t len;
  struct conn_id_s_t conn_id_s;
	int is_sample;
  enum step_t step;
};


// struct data_evt {
//   uint64_t tgid_fd;
// };


static inline void my_strcpy(char *dest, const char *src, int n) {
    int i = 0;
	int LIMIT = n;
    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
		if (i >= LIMIT) {
			i--;
			break;
		}
    }
    dest[i] = '\0';
}


struct data_args {
  // Represents the function from which this argument group originates.
  enum source_function_t source_fn;

  // Did the data event call sock_sendmsg/sock_recvmsg.
  // Used to filter out read/write and readv/writev calls that are not to sockets.
  int sock_event;

  int32_t fd;

  // For send()/recv()/write()/read().
  const char* buf;

  // For sendmsg()/recvmsg()/writev()/readv().
  const struct iovec* iov;
  size_t iovlen;

  // For sendmmsg()
  unsigned int* msg_len;
  size_t* ssl_ex_len;
};
struct close_args {
  uint32_t fd;
};

struct connect_args {
  const struct sockaddr* addr;
  int32_t fd;
};

struct accept_args {
  struct sockaddr* addr;
  struct socket* sock_alloc_socket;
};



union sockaddr_t {
  struct sockaddr_in in4;
  struct sockaddr_in6 in6;
};
struct conn_info_t {
  // Connection identifier (PID, FD, etc.).
  struct conn_id_t conn_id;
  uint64_t read_bytes;
  uint64_t write_bytes;

  // IP address of the local endpoint.
  union sockaddr_t laddr;
  union sockaddr_t raddr;

  // The protocol of traffic on the connection (HTTP, MySQL, etc.).
  enum traffic_protocol_t protocol;
  // Classify traffic as requests, responses or mixed.
  enum endpoint_role_t role;
};


struct conn_evt_t {
  struct conn_info_t conn_info;
  enum conn_type_t  conn_type;
	uint64_t ts;
};

static __always_inline int is_redis_protocol(const char *old_buf, size_t count) {
  if (count < 3) {
    return false;
  }
  
  char buf[1] = {};
  bpf_probe_read_user(buf, 1, old_buf);
  const char first_byte = buf[0];
  if (  // Simple strings start with +
      first_byte != '+' &&
      // Errors start with -
      first_byte != '-' &&
      // Integers start with :
      first_byte != ':' &&
      // Bulk strings start with $
      first_byte != '$' &&
      // Arrays start with *
      first_byte != '*') {
    return false;
  }
  return true;
}

static __always_inline int is_http_protocol(const char *old_buf, size_t count) {
  if (count < 16) {
    return 0;
  }
  char buf[4] = {};
  bpf_probe_read_user(buf, 4, old_buf);
  if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
    return 1;
  }
  if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') {
    return 1;
  }
  if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
    return 1;
  }
  return 0;
}

static __always_inline struct protocol_message_t infer_protocol(const char *buf, size_t count, struct conn_info_t *conn_info) {
  struct protocol_message_t protocol_message;
  protocol_message.protocol = kProtocolUnknown;
  protocol_message.type = kUnknown;
  if (is_http_protocol(buf, count)) {
    protocol_message.protocol = kProtocolHTTP;
  } else if (is_redis_protocol(buf, count)) {
    protocol_message.protocol = kProtocolRedis;
  }
  conn_info->protocol = protocol_message.protocol;
}

#endif		
