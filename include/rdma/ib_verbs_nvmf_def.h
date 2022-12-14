#ifndef IB_VERBS_EXP_DEF_H
#define IB_VERBS_EXP_DEF_H

enum ib_nvmf_offload_type {
	IB_NVMF_WRITE_OFFLOAD		 = (1ULL << 0),
	IB_NVMF_READ_OFFLOAD		 = (1ULL << 1),
	IB_NVMF_READ_WRITE_OFFLOAD	 = (1ULL << 2),
	IB_NVMF_READ_WRITE_FLUSH_OFFLOAD = (1ULL << 3),
};

struct ib_nvmf_srq_attr {
	u64 cmd_unknown_namespace_cnt;
};

struct ib_nvmf_init_data {
	enum ib_nvmf_offload_type	type;
	u8				log_max_namespace;
	u32				cmd_size;
	u8				data_offset;
	u8				log_max_io_size;
	u8				nvme_memory_log_page_size;
	u8				staging_buffer_log_page_size;
	u16				staging_buffer_number_of_pages;
	u32				staging_buffer_page_offset;
	u32				nvme_queue_size;
	u64				*staging_buffer_pas;
};

struct ib_nvmf_caps {
	u32 offload_type_dc; /* bitmap of ib_nvmf_offload_type enum */
	u32 offload_type_rc; /* bitmap of ib_nvmf_offload_type enum */
	u32 max_namespace;
	u32 max_staging_buffer_sz;
	u32 min_staging_buffer_sz;
	u32 max_io_sz;
	u32 max_be_ctrl;
	u32 max_queue_sz;
	u32 min_queue_sz;
	u32 min_cmd_size;
	u32 max_cmd_size;
	u8  max_data_offset;
	u32 min_cmd_timeout_us; /* 0 means use HCA default value */
	u32 max_cmd_timeout_us; /* 0 means use HCA default value */
	u32 max_frontend_nsid; /* 0 means any frontend nsid is allowed */
};

enum ib_qp_offload_type {
	IB_QP_OFFLOAD_NVMF = 1,
};

#endif
