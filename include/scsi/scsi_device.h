#ifndef COMPAT_SCSI_SCSI_DEVICE_H
#define COMPAT_SCSI_SCSI_DEVICE_H

#include "../../compat/config.h"

#include_next <scsi/scsi_device.h>

#ifndef HAVE_ENUM_SCSI_SCAN_MODE
enum scsi_scan_mode {
	SCSI_SCAN_INITIAL = 0,
	SCSI_SCAN_RESCAN,
	SCSI_SCAN_MANUAL,
};
#endif

#endif	/* COMPAT_SCSI_SCSI_DEVICE_H */
