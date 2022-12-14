#ifndef IB_VERBS_EXP_H
#define IB_VERBS_EXP_H

#include <rdma/ib_verbs.h>
struct ib_nvmf_ctrl {
	struct ib_srq   *srq;
	u32             id;
	atomic_t        usecnt; /* count all attached namespaces */
	void            (*event_handler)(struct ib_event *, void *);
	void            *be_context;
};

struct ib_nvmf_backend_ctrl_init_attr {
	void            (*event_handler)(struct ib_event *, void *);
	void            *be_context;
	u32             cq_page_offset;
	u32             sq_page_offset;
	u8              cq_log_page_size;
	u8              sq_log_page_size;
	u16             initial_cqh_db_value;
	u16             initial_sqt_db_value;
	u32             cmd_timeout_us;
	u64             cqh_dbr_addr;
	u64             sqt_dbr_addr;
	u64             cq_pas;
	u64             sq_pas;
};

struct ib_nvmf_ns {
	struct ib_nvmf_ctrl     *ctrl;
	u32                     nsid;
};

struct ib_nvmf_ns_init_attr {
	u32             frontend_namespace;
	u32             backend_namespace;
	u16             lba_data_size;
	u16             backend_ctrl_id;
};

struct ib_nvmf_ns_attr {
	u64     num_read_cmd;
	u64     num_read_blocks;
	u64     num_write_cmd;
	u64     num_write_blocks;
	u64     num_write_inline_cmd;
	u64     num_flush_cmd;
	u64     num_error_cmd;
	u64     num_backend_error_cmd;
	u64     last_read_latency;
	u64     last_write_latency;
	u64     queue_depth;
};

int ib_query_nvmf_ns(struct ib_nvmf_ns *ns, struct ib_nvmf_ns_attr *ns_attr);
struct ib_nvmf_ctrl *ib_create_nvmf_backend_ctrl(struct ib_srq *srq,
		struct ib_nvmf_backend_ctrl_init_attr *init_attr);
int ib_destroy_nvmf_backend_ctrl(struct ib_nvmf_ctrl *ctrl);
struct ib_nvmf_ns *ib_attach_nvmf_ns(struct ib_nvmf_ctrl *ctrl,
		struct ib_nvmf_ns_init_attr *init_attr);
int ib_detach_nvmf_ns(struct ib_nvmf_ns *ns);

#endif
