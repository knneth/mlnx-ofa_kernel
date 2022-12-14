#ifndef _COMPAT_SCSI_SCSI_H
#define _COMPAT_SCSI_SCSI_H

#include "../../compat/config.h"

#include_next <scsi/scsi.h>

#ifndef SCSI_MAX_SG_CHAIN_SEGMENTS
#define SCSI_MAX_SG_CHAIN_SEGMENTS SG_MAX_SEGMENTS
#endif

#endif /* _COMPAT_SCSI_SCSI_H */
