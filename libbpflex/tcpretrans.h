// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Hengqi Chen */
#ifndef __TCPSTATES_H
#define __TCPSTATES_H

#define TASK_COMM_LEN	16

struct event {
	__u64 skaddr;
	__u64 ts_us;
	__u64 delta_us;
	__u32 pid;
	__u32 tid;
	int oldstate;
	int newstate;
	__u16 family;
	__u16 sport;
	__u16 dport;
	__u16 protocol;
	char task[TASK_COMM_LEN];
	unsigned long long saddr;
        unsigned long long daddr;
	__u16 conn_passive;
};

struct list {
	struct event socket_details;
        struct list *next;
};

struct list *head;
struct list *head_conn;
struct list *sharedList;
#endif /* __TCPSTATES_H */
