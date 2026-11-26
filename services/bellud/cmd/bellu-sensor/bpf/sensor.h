/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#ifndef BELLU_SENSOR_H
#define BELLU_SENSOR_H

/* Wire layout shared with loader.go (rawEvent). Keep both in sync; all fields little-endian. */
enum bellu_event_kind {
	BELLU_EXEC = 1,
	BELLU_FILE_WRITE = 2,
	BELLU_CONNECT = 3,
	BELLU_PRIV_CHANGE = 4,
	BELLU_CONTAINER_ESCAPE = 5,
	BELLU_SHELL_IN_CONTAINER = 6,
};

#define BELLU_PATH_LEN 256
#define BELLU_ARGS_LEN 256
#define BELLU_COMM_LEN 16

struct bellu_event {
	__u64 ts_ns;
	__u64 cgroup_id;
	__u32 kind;
	__u32 pid;
	__u32 uid;
	__u32 in_container; /* 1 when the task runs in a non-initial PID namespace */
	__u32 addr4;        /* connect: IPv4 address, network order */
	__u16 port;         /* connect: host order */
	__u16 family;
	char comm[BELLU_COMM_LEN];
	char path[BELLU_PATH_LEN];
	char args[BELLU_ARGS_LEN];
};

#endif
