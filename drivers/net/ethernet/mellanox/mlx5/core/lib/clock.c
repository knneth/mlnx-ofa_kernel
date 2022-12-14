/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/clocksource.h>
#include <linux/highmem.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/indirect_call_wrapper.h>
#include <linux/time64.h>
#include <rdma/mlx5-abi.h>
#include "lib/eq.h"
#include "en.h"
#include "clock.h"

enum {
	MLX5_CYCLES_SHIFT	= 23
};

enum {
	MLX5_PIN_MODE_IN		= 0x0,
	MLX5_PIN_MODE_OUT		= 0x1,
};

enum {
	MLX5_OUT_PATTERN_PULSE		= 0x0,
	MLX5_OUT_PATTERN_PERIODIC	= 0x1,
};

enum {
	MLX5_EVENT_MODE_DISABLE	= 0x0,
	MLX5_EVENT_MODE_REPETETIVE	= 0x1,
	MLX5_EVENT_MODE_ONCE_TILL_ARM	= 0x2,
};

enum {
	MLX5_MTPPS_FS_ENABLE			= BIT(0x0),
	MLX5_MTPPS_FS_PATTERN			= BIT(0x2),
	MLX5_MTPPS_FS_PIN_MODE			= BIT(0x3),
	MLX5_MTPPS_FS_TIME_STAMP		= BIT(0x4),
	MLX5_MTPPS_FS_OUT_PULSE_DURATION	= BIT(0x5),
	MLX5_MTPPS_FS_ENH_OUT_PER_ADJ		= BIT(0x7),
	MLX5_MTPPS_FS_NPPS_PERIOD               = BIT(0x9),
	MLX5_MTPPS_FS_OUT_PULSE_DURATION_NS     = BIT(0xa),
};

enum {
	MLX5_MTUTC_OPERATION_SET_TIME_IMMEDIATE   = 0x1,
	MLX5_MTUTC_OPERATION_ADJUST_TIME          = 0x2,
	MLX5_MTUTC_OPERATION_ADJUST_FREQ_UTC      = 0x3,
};

enum {
	MLX5_MTUTC_TIME_STAMP_MODE_INTERNAL_TIMER = 0x0,
	MLX5_MTUTC_TIME_STAMP_MODE_REAL_TIME      = 0x1,
};

#define REAL_TIME_MODE(clock)			\
	((clock)->time_stamp_mode ==		\
	 MLX5_MTUTC_TIME_STAMP_MODE_REAL_TIME)

#define REAL_TIME_TO_NS(hi, low) (((u64)hi) * NSEC_PER_SEC + ((u64)low))

static u64 mlx5_read_clock(struct mlx5_core_dev *dev,
			   struct ptp_system_timestamp *sts)
{
	struct mlx5_clock *clock = &dev->clock;

	u32 timer_h, timer_h1, timer_l;

	timer_h = ioread32be(clock->addr_h);
	ptp_read_system_prets(sts);
	timer_l = ioread32be(clock->addr_l);
	ptp_read_system_postts(sts);
	timer_h1 = ioread32be(clock->addr_h);
	if (timer_h != timer_h1) {
		/* wrap around */
		ptp_read_system_prets(sts);
		timer_l = ioread32be(clock->addr_l);
		ptp_read_system_postts(sts);
	}

	if (REAL_TIME_MODE(clock))
		return REAL_TIME_TO_NS(timer_h, timer_l);

	return (u64)timer_l | (u64)timer_h1 << 32;
}

static u64 read_internal_timer(const struct cyclecounter *cc)
{
	struct mlx5_clock *clock = container_of(cc, struct mlx5_clock, cycles);
	struct mlx5_core_dev *mdev = container_of(clock, struct mlx5_core_dev,
						  clock);

	return mlx5_read_clock(mdev, NULL) & cc->mask;
}

static void mlx5_update_clock_info_page(struct mlx5_core_dev *mdev)
{
	struct mlx5_ib_clock_info *clock_info = mdev->clock_info;
	struct mlx5_clock *clock = &mdev->clock;
	u32 sign;

	if (!clock_info)
		return;

	sign = smp_load_acquire(&clock_info->sign);
	smp_store_mb(clock_info->sign,
		     sign | MLX5_IB_CLOCK_INFO_KERNEL_UPDATING);

	clock_info->cycles = clock->tc.cycle_last;
	clock_info->mult   = clock->cycles.mult;
	clock_info->nsec   = clock->tc.nsec;
	clock_info->frac   = clock->tc.frac;

	smp_store_release(&clock_info->sign,
			  sign + MLX5_IB_CLOCK_INFO_KERNEL_UPDATING * 2);
}

static void mlx5_pps_out(struct work_struct *work)
{
	struct mlx5_pps *pps_info = container_of(work, struct mlx5_pps,
						 out_work);
	struct mlx5_clock *clock = container_of(pps_info, struct mlx5_clock,
						pps_info);
	struct mlx5_core_dev *mdev = container_of(clock, struct mlx5_core_dev,
						  clock);
	u32 in[MLX5_ST_SZ_DW(mtpps_reg)] = {0};
	unsigned long flags;
	int i;

	for (i = 0; i < clock->ptp_info.n_pins; i++) {
		u64 tstart;

		write_seqlock_irqsave(&clock->lock, flags);
		tstart = clock->pps_info.start[i];
		clock->pps_info.start[i] = 0;
		write_sequnlock_irqrestore(&clock->lock, flags);
		if (!tstart)
			continue;

		MLX5_SET(mtpps_reg, in, pin, i);
		MLX5_SET64(mtpps_reg, in, time_stamp, tstart);
		MLX5_SET(mtpps_reg, in, field_select, MLX5_MTPPS_FS_TIME_STAMP);
		mlx5_set_mtpps(mdev, in, sizeof(in));
	}
}

static void mlx5_timestamp_overflow(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct mlx5_clock *clock = container_of(dwork, struct mlx5_clock,
						overflow_work);
	unsigned long flags;

	write_seqlock_irqsave(&clock->lock, flags);
	timecounter_read(&clock->tc);
	mlx5_update_clock_info_page(clock->mdev);
	write_sequnlock_irqrestore(&clock->lock, flags);
	schedule_delayed_work(&clock->overflow_work, clock->overflow_period);
}

static int mlx5_ptp_settime(struct ptp_clock_info *ptp,
			    const struct timespec64 *ts)
{
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						 ptp_info);
	u64 ns = timespec64_to_ns(ts);
	unsigned long flags;

	write_seqlock_irqsave(&clock->lock, flags);
	timecounter_init(&clock->tc, &clock->cycles, ns);
	mlx5_update_clock_info_page(clock->mdev);
	write_sequnlock_irqrestore(&clock->lock, flags);

	return 0;
}

static int mlx5_ptp_gettimex(struct ptp_clock_info *ptp, struct timespec64 *ts,
			     struct ptp_system_timestamp *sts)
{
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						ptp_info);
	struct mlx5_core_dev *mdev = container_of(clock, struct mlx5_core_dev,
						  clock);
	unsigned long flags;
	u64 cycles, ns;

	write_seqlock_irqsave(&clock->lock, flags);
	cycles = mlx5_read_clock(mdev, sts);
	ns = timecounter_cyc2time(&clock->tc, cycles);
	write_sequnlock_irqrestore(&clock->lock, flags);

	*ts = ns_to_timespec64(ns);

	return 0;
}

static int mlx5_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						ptp_info);
	unsigned long flags;

	write_seqlock_irqsave(&clock->lock, flags);
	timecounter_adjtime(&clock->tc, delta);
	mlx5_update_clock_info_page(clock->mdev);
	write_sequnlock_irqrestore(&clock->lock, flags);

	return 0;
}

static int mlx5_ptp_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
	u64 adj;
	u32 diff;
	unsigned long flags;
	int neg_adj = 0;
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						ptp_info);

	if (delta < 0) {
		neg_adj = 1;
		delta = -delta;
	}

	adj = clock->nominal_c_mult;
	adj *= delta;
	diff = div_u64(adj, 1000000000ULL);

	write_seqlock_irqsave(&clock->lock, flags);
	timecounter_read(&clock->tc);
	clock->cycles.mult = neg_adj ? clock->nominal_c_mult - diff :
				       clock->nominal_c_mult + diff;
	mlx5_update_clock_info_page(clock->mdev);
	write_sequnlock_irqrestore(&clock->lock, flags);

	return 0;
}

int mlx5_query_mtutc(struct mlx5_core_dev *dev, u32 *mtutc, u32 mtutc_size)
{
	u32 in[MLX5_ST_SZ_DW(mtutc_reg)] = {0};

	if (!MLX5_CAP_MCAM_REG(dev, mtutc))
		return -EOPNOTSUPP;

	return mlx5_core_access_reg(dev, in, sizeof(in), mtutc,
				    mtutc_size, MLX5_REG_MTUTC, 0, 0);
}

int mlx5_set_mtutc(struct mlx5_core_dev *dev, u32 *mtutc, u32 mtutc_size)
{
	u32 out[MLX5_ST_SZ_DW(mtutc_reg)] = {0};

	if (!MLX5_CAP_MCAM_REG(dev, mtutc))
		return -EOPNOTSUPP;

	return mlx5_core_access_reg(dev, mtutc, mtutc_size, out,
				    sizeof(out), MLX5_REG_MTUTC, 0, 1);
}

static void mlx5_get_mtutc_caps(struct mlx5_core_dev *mdev)
{
	u32 out[MLX5_ST_SZ_DW(mtutc_reg)] = {0};
	struct mlx5_clock *clock = &mdev->clock;
	int err;

	err = mlx5_query_mtutc(mdev, out, sizeof(out));
	if (err)
		mlx5_core_dbg(mdev, "Failed querying MTUTC. err = %d\n", err);
	else
		clock->time_stamp_mode = MLX5_GET(mtutc_reg, out, time_stamp_mode);

	mlx5_core_dbg(mdev, "Time stamp mode = 0x%x\n", clock->time_stamp_mode);
}

static int mlx5_ptp_real_time_settime(struct ptp_clock_info *ptp,
				      const struct timespec64 *ts)
{
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						ptp_info);
	struct mlx5_core_dev *mdev = clock->mdev;
	u32 in[MLX5_ST_SZ_DW(mtutc_reg)] = {0};

	if (!MLX5_CAP_MCAM_FEATURE(mdev, ptpcyc2realtime_modify))
		return 0;

	mlx5_core_dbg(mdev, "tv_sec = %lld, tv_nsec = %ld\n",
		      ts->tv_sec, ts->tv_nsec);

	if (ts->tv_sec < 0 || ts->tv_sec > U32_MAX ||
	    ts->tv_nsec < 0 || ts->tv_nsec > NSEC_PER_SEC)
		return -EINVAL;

	MLX5_SET(mtutc_reg, in, operation, MLX5_MTUTC_OPERATION_SET_TIME_IMMEDIATE);
	MLX5_SET(mtutc_reg, in, utc_sec, ts->tv_sec);
	MLX5_SET(mtutc_reg, in, utc_nsec, ts->tv_nsec);

	return mlx5_set_mtutc(mdev, in, sizeof(in));
}

static int mlx5_ptp_real_time_gettimex64(struct ptp_clock_info *ptp,
					 struct timespec64 *ts,
					 struct ptp_system_timestamp *sts)
{
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						ptp_info);
	struct mlx5_core_dev *mdev = clock->mdev;
	u64 time;

	time = mlx5_read_clock(mdev, sts);
	*ts = ns_to_timespec64(time);
	mlx5_core_dbg(mdev, "time = %llu\n", time);

	return 0;
}

static int mlx5_ptp_real_time_adjtime(struct ptp_clock_info *ptp,
				      s64 delta)
{
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						ptp_info);
	struct mlx5_core_dev *mdev = clock->mdev;
	u32 in[MLX5_ST_SZ_DW(mtutc_reg)] = {0};

	if (!MLX5_CAP_MCAM_FEATURE(mdev, ptpcyc2realtime_modify))
		return 0;

	mlx5_core_dbg(mdev, "delta = %lld\n", delta);

	/* HW time adjustment range is s16. If out of range, settime instead */
	if (delta < S16_MIN || delta > S16_MAX) {
		struct timespec64 ts;
		s64 ns;

		mlx5_ptp_real_time_gettimex64(ptp, &ts, NULL);
		ns = timespec64_to_ns(&ts) + delta;
		ts = ns_to_timespec64(ns);

		return mlx5_ptp_real_time_settime(ptp, &ts);
	}

	MLX5_SET(mtutc_reg, in, operation, MLX5_MTUTC_OPERATION_ADJUST_TIME);
	MLX5_SET(mtutc_reg, in, time_adjustment, delta);

	return mlx5_set_mtutc(mdev, in, sizeof(in));
}

static int mlx5_ptp_real_time_adjfine(struct ptp_clock_info *ptp,
				      long scaled_ppm)
{
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						ptp_info);
	struct mlx5_core_dev *mdev = clock->mdev;
	u32 in[MLX5_ST_SZ_DW(mtutc_reg)] = {0};
	s32 ppb;

	if (!MLX5_CAP_MCAM_FEATURE(mdev, ptpcyc2realtime_modify))
		return 0;

	ppb = scaled_ppm_to_ppb(scaled_ppm);
	mlx5_core_dbg(mdev, "scaled_ppm = %lu, ppb = %d\n", scaled_ppm, ppb);
	MLX5_SET(mtutc_reg, in, operation, MLX5_MTUTC_OPERATION_ADJUST_FREQ_UTC);
	MLX5_SET(mtutc_reg, in, freq_adjustment, ppb);

	return mlx5_set_mtutc(mdev, in, sizeof(in));
}

static int mlx5_extts_configure(struct ptp_clock_info *ptp,
				struct ptp_clock_request *rq,
				int on)
{
	struct mlx5_clock *clock =
			container_of(ptp, struct mlx5_clock, ptp_info);
	struct mlx5_core_dev *mdev =
			container_of(clock, struct mlx5_core_dev, clock);
	u32 in[MLX5_ST_SZ_DW(mtpps_reg)] = {0};
	u32 field_select = 0;
	u8 pin_mode = 0;
	u8 pattern = 0;
	int pin = -1;
	int err = 0;

	if (!MLX5_PPS_CAP(mdev))
		return -EOPNOTSUPP;

	/* Reject requests with unsupported flags */
	if (rq->extts.flags & ~(PTP_ENABLE_FEATURE |
				PTP_RISING_EDGE |
				PTP_FALLING_EDGE |
				PTP_STRICT_FLAGS))
		return -EOPNOTSUPP;

	/* Reject requests to enable time stamping on both edges. */
	if ((rq->extts.flags & PTP_STRICT_FLAGS) &&
	    (rq->extts.flags & PTP_ENABLE_FEATURE) &&
	    (rq->extts.flags & PTP_EXTTS_EDGES) == PTP_EXTTS_EDGES)
		return -EOPNOTSUPP;

	if (rq->extts.index >= clock->ptp_info.n_pins)
		return -EINVAL;

	pin = ptp_find_pin(clock->ptp, PTP_PF_EXTTS, rq->extts.index);
	if (pin < 0)
		return -EBUSY;

	if (on) {
		pin_mode = MLX5_PIN_MODE_IN;
		pattern = !!(rq->extts.flags & PTP_FALLING_EDGE);
		field_select = MLX5_MTPPS_FS_PIN_MODE |
			       MLX5_MTPPS_FS_PATTERN |
			       MLX5_MTPPS_FS_ENABLE;
	} else {
		field_select = MLX5_MTPPS_FS_ENABLE;
	}

	MLX5_SET(mtpps_reg, in, pin, pin);
	MLX5_SET(mtpps_reg, in, pin_mode, pin_mode);
	MLX5_SET(mtpps_reg, in, pattern, pattern);
	MLX5_SET(mtpps_reg, in, enable, on);
	MLX5_SET(mtpps_reg, in, field_select, field_select);

	err = mlx5_set_mtpps(mdev, in, sizeof(in));
	if (err)
		return err;

	return mlx5_set_mtppse(mdev, pin, 0,
			       MLX5_EVENT_MODE_REPETETIVE & on);
}

static u64 find_target_cycles(struct mlx5_core_dev *mdev, s64 target_ns)
{
	struct mlx5_clock *clock = &mdev->clock;
	u64 cycles_now, cycles_delta;
	u64 nsec_now, nsec_delta;
	unsigned long flags;

	cycles_now = mlx5_read_clock(mdev, NULL);
	write_seqlock_irqsave(&clock->lock, flags);
	nsec_now = timecounter_cyc2time(&clock->tc, cycles_now);
	nsec_delta = target_ns - nsec_now;
	cycles_delta = div64_u64(nsec_delta << clock->cycles.shift,
				 clock->cycles.mult);
	write_sequnlock_irqrestore(&clock->lock, flags);

	return cycles_now + cycles_delta;
}

static u64 perout_conf_internal_timer(struct mlx5_core_dev *mdev,
				      s64 sec, u32 nsec)
{
	struct timespec64 ts;
	s64 target_ns;

	ts.tv_sec = sec;
	ts.tv_nsec = nsec;
	target_ns = timespec64_to_ns(&ts);

	return find_target_cycles(mdev, target_ns);
}

static u64 perout_conf_real_time(s64 sec, u32 nsec)
{
	return (u64)nsec | (u64)sec << 32;
}

static int
perout_conf_no_npps(struct mlx5_core_dev *mdev, struct ptp_clock_request *rq,
		    u32 *field_select, u64 *time_stamp, bool real_time)
{
	struct ptp_clock_time *start;
	struct timespec64 ts;
	s64 ns;

	ts.tv_nsec = rq->perout.period.nsec;
	ts.tv_sec = rq->perout.period.sec;
	ns = timespec64_to_ns(&ts);

	if ((ns >> 1) != 500000000LL)
		return -EINVAL;

	start = &rq->perout.start;

	*time_stamp = real_time ?
		      perout_conf_real_time(start->sec, start->nsec) :
		      perout_conf_internal_timer(mdev, start->sec, start->nsec);
	*field_select |= MLX5_MTPPS_FS_TIME_STAMP;

	return 0;
}

static int
perout_conf_npps_real_time(struct ptp_clock_request *rq, u32 *field_select,
			   u32 *out_pulse_duration_ns, u64 *npps_period,
			   u64 *time_stamp)
{
	u32 tmp_out_pulse_duration_ns;
	struct timespec64 ts;
	u64 npps_ns;

	/* out_pulse_duration_ns should be up to 10% of the pulse period */
	ts.tv_sec = rq->perout.period.sec;
	ts.tv_nsec = rq->perout.period.nsec;
	npps_ns = timespec64_to_ns(&ts);
	tmp_out_pulse_duration_ns = npps_ns;
	do_div(tmp_out_pulse_duration_ns, 10);

	/* out_pulse_duration_ns is 30b, and greater than zero */
	tmp_out_pulse_duration_ns &= 0x3fffffff;
	if (!tmp_out_pulse_duration_ns)
		tmp_out_pulse_duration_ns = 1;

	*time_stamp = perout_conf_real_time(rq->perout.start.sec,
					    rq->perout.start.nsec);
	*npps_period = perout_conf_real_time(rq->perout.period.sec,
					     rq->perout.period.nsec);
	*out_pulse_duration_ns = tmp_out_pulse_duration_ns;
	*field_select |= MLX5_MTPPS_FS_TIME_STAMP |
			 MLX5_MTPPS_FS_NPPS_PERIOD |
			 MLX5_MTPPS_FS_OUT_PULSE_DURATION_NS;

	return 0;
}

static int mlx5_perout_configure(struct ptp_clock_info *ptp,
				 struct ptp_clock_request *rq,
				 int on)
{
	struct mlx5_clock *clock =
			container_of(ptp, struct mlx5_clock, ptp_info);
	struct mlx5_core_dev *mdev =
			container_of(clock, struct mlx5_core_dev, clock);
	u32 in[MLX5_ST_SZ_DW(mtpps_reg)] = {0};
	u32 out_pulse_duration_ns = 0;
	u32 field_select = 0;
	u64 npps_period = 0;
	u64 time_stamp = 0;
	u8 pin_mode = 0;
	u8 pattern = 0;
	int pin = -1;
	int err = 0;

	if (!MLX5_PPS_CAP(mdev))
		return -EOPNOTSUPP;

	/* Reject requests with unsupported flags */
	if (rq->perout.flags)
		return -EOPNOTSUPP;

	if (rq->perout.index >= clock->ptp_info.n_pins)
		return -EINVAL;

	pin = ptp_find_pin(clock->ptp, PTP_PF_PEROUT,
			   rq->perout.index);
	if (pin < 0)
		return -EBUSY;

	field_select = MLX5_MTPPS_FS_ENABLE;

	if (on) {
		pin_mode = MLX5_PIN_MODE_OUT;
		pattern = MLX5_OUT_PATTERN_PERIODIC;
		field_select |= MLX5_MTPPS_FS_PIN_MODE |
				MLX5_MTPPS_FS_PATTERN;

		if (REAL_TIME_MODE(clock) && rq->perout.start.sec > U32_MAX)
			return -EINVAL;

		if (REAL_TIME_MODE(clock) &&
		    MLX5_CAP_MCAM_FEATURE(mdev, npps_period) &&
		    MLX5_CAP_MCAM_FEATURE(mdev, out_pulse_duration_ns))
			err = perout_conf_npps_real_time(rq, &field_select, &out_pulse_duration_ns,
							 &npps_period, &time_stamp);
		else
			err = perout_conf_no_npps(mdev, rq, &field_select, &time_stamp,
						  REAL_TIME_MODE(clock));
		if (err)
			return err;
	}

	MLX5_SET(mtpps_reg, in, pin, pin);
	MLX5_SET(mtpps_reg, in, pin_mode, pin_mode);
	MLX5_SET(mtpps_reg, in, pattern, pattern);
	MLX5_SET(mtpps_reg, in, enable, on);
	MLX5_SET64(mtpps_reg, in, time_stamp, time_stamp);
	MLX5_SET(mtpps_reg, in, field_select, field_select);
	MLX5_SET64(mtpps_reg, in, npps_period, npps_period);
	MLX5_SET(mtpps_reg, in, out_pulse_duration_ns, out_pulse_duration_ns);

	err = mlx5_set_mtpps(mdev, in, sizeof(in));
	if (err)
		return err;

	/* When using npps, mtppse configuration can be skipped */
	if (npps_period)
		return 0;

	return mlx5_set_mtppse(mdev, pin, 0,
			       MLX5_EVENT_MODE_REPETETIVE & on);
}

static int mlx5_pps_configure(struct ptp_clock_info *ptp,
			      struct ptp_clock_request *rq,
			      int on)
{
	struct mlx5_clock *clock =
			container_of(ptp, struct mlx5_clock, ptp_info);

	clock->pps_info.enabled = !!on;
	return 0;
}

static int mlx5_ptp_enable(struct ptp_clock_info *ptp,
			   struct ptp_clock_request *rq,
			   int on)
{
	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		return mlx5_extts_configure(ptp, rq, on);
	case PTP_CLK_REQ_PEROUT:
		return mlx5_perout_configure(ptp, rq, on);
	case PTP_CLK_REQ_PPS:
		return mlx5_pps_configure(ptp, rq, on);
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

enum {
	MLX5_MTPPS_REG_CAP_PIN_X_MODE_SUPPORT_PPS_IN = BIT(0),
	MLX5_MTPPS_REG_CAP_PIN_X_MODE_SUPPORT_PPS_OUT = BIT(1),
};

static int mlx5_ptp_verify(struct ptp_clock_info *ptp, unsigned int pin,
			   enum ptp_pin_function func, unsigned int chan)
{
	struct mlx5_clock *clock = container_of(ptp, struct mlx5_clock,
						ptp_info);

	switch (func) {
	case PTP_PF_NONE:
		return 0;
	case PTP_PF_EXTTS:
		return !(clock->pps_info.pin_caps[pin] &
			 MLX5_MTPPS_REG_CAP_PIN_X_MODE_SUPPORT_PPS_IN);
	case PTP_PF_PEROUT:
		return !(clock->pps_info.pin_caps[pin] &
			 MLX5_MTPPS_REG_CAP_PIN_X_MODE_SUPPORT_PPS_OUT);
	default:
		return -EOPNOTSUPP;
	}

	return -EOPNOTSUPP;
}

static const struct ptp_clock_info mlx5_ptp_clock_info = {
	.owner		= THIS_MODULE,
	.name		= "mlx5_ptp",
	.max_adj	= 100000000,
	.n_alarm	= 0,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.n_pins		= 0,
	.pps		= 0,
	.adjfreq	= mlx5_ptp_adjfreq,
	.adjtime	= mlx5_ptp_adjtime,
	.gettimex64	= mlx5_ptp_gettimex,
	.settime64	= mlx5_ptp_settime,
	.enable		= NULL,
	.verify		= NULL,
};

static int mlx5_query_mtpps_pin_mode(struct mlx5_core_dev *mdev, u8 pin,
				     u32 *mtpps, u32 mtpps_size)
{
	u32 in[MLX5_ST_SZ_DW(mtpps_reg)] = {};

	MLX5_SET(mtpps_reg, in, pin, pin);

	return mlx5_core_access_reg(mdev, in, sizeof(in), mtpps,
				    mtpps_size, MLX5_REG_MTPPS, 0, 0);
}

static int mlx5_get_pps_pin_mode(struct mlx5_clock *clock, u8 pin)
{
	struct mlx5_core_dev *mdev = clock->mdev;
	u32 out[MLX5_ST_SZ_DW(mtpps_reg)] = {};
	u8 mode;
	int err;

	err = mlx5_query_mtpps_pin_mode(mdev, pin, out, sizeof(out));
	if (err || !MLX5_GET(mtpps_reg, out, enable))
		return PTP_PF_NONE;

	mode = MLX5_GET(mtpps_reg, out, pin_mode);

	if (mode == MLX5_PIN_MODE_IN)
		return PTP_PF_EXTTS;
	else if (mode == MLX5_PIN_MODE_OUT)
		return PTP_PF_PEROUT;

	return PTP_PF_NONE;
}

static const struct ptp_clock_info mlx5_ptp_real_time_clock_info = {
	.owner		= THIS_MODULE,
	.name		= "mlx5_ptp_rt",
	.max_adj	= 100000000,
	.n_alarm	= 0,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.n_pins		= 0,
	.pps		= 0,
	.adjfine	= mlx5_ptp_real_time_adjfine,
	.adjtime	= mlx5_ptp_real_time_adjtime,
	.gettimex64	= mlx5_ptp_real_time_gettimex64,
	.settime64	= mlx5_ptp_real_time_settime,
	.enable		= NULL,
	.verify		= NULL,
};

static int mlx5_init_pin_config(struct mlx5_clock *clock)
{
	int i;

	clock->ptp_info.pin_config =
			kcalloc(clock->ptp_info.n_pins,
				sizeof(*clock->ptp_info.pin_config),
				GFP_KERNEL);
	if (!clock->ptp_info.pin_config)
		return -ENOMEM;
	clock->ptp_info.enable = mlx5_ptp_enable;
	clock->ptp_info.verify = mlx5_ptp_verify;
	clock->ptp_info.pps = 1;

	for (i = 0; i < clock->ptp_info.n_pins; i++) {
		snprintf(clock->ptp_info.pin_config[i].name,
			 sizeof(clock->ptp_info.pin_config[i].name),
			 "mlx5_pps%d", i);
		clock->ptp_info.pin_config[i].index = i;
		clock->ptp_info.pin_config[i].func = mlx5_get_pps_pin_mode(clock, i);
		clock->ptp_info.pin_config[i].chan = 0;
	}

	return 0;
}

static void mlx5_get_pps_caps(struct mlx5_core_dev *mdev)
{
	struct mlx5_clock *clock = &mdev->clock;
	u32 out[MLX5_ST_SZ_DW(mtpps_reg)] = {0};

	mlx5_query_mtpps(mdev, out, sizeof(out));

	clock->ptp_info.n_pins = MLX5_GET(mtpps_reg, out,
					  cap_number_of_pps_pins);
	clock->ptp_info.n_ext_ts = MLX5_GET(mtpps_reg, out,
					    cap_max_num_of_pps_in_pins);
	clock->ptp_info.n_per_out = MLX5_GET(mtpps_reg, out,
					     cap_max_num_of_pps_out_pins);

	clock->pps_info.pin_caps[0] = MLX5_GET(mtpps_reg, out, cap_pin_0_mode);
	clock->pps_info.pin_caps[1] = MLX5_GET(mtpps_reg, out, cap_pin_1_mode);
	clock->pps_info.pin_caps[2] = MLX5_GET(mtpps_reg, out, cap_pin_2_mode);
	clock->pps_info.pin_caps[3] = MLX5_GET(mtpps_reg, out, cap_pin_3_mode);
	clock->pps_info.pin_caps[4] = MLX5_GET(mtpps_reg, out, cap_pin_4_mode);
	clock->pps_info.pin_caps[5] = MLX5_GET(mtpps_reg, out, cap_pin_5_mode);
	clock->pps_info.pin_caps[6] = MLX5_GET(mtpps_reg, out, cap_pin_6_mode);
	clock->pps_info.pin_caps[7] = MLX5_GET(mtpps_reg, out, cap_pin_7_mode);
}

static void ts_next_sec(struct timespec64 *ts)
{
	ts->tv_sec += 1;
	ts->tv_nsec = 0;
}

static u64 pps_perout_internal_timer(struct mlx5_clock *clock)
{
	struct timespec64 ts;
	s64 target_ns;

	mlx5_ptp_gettimex(&clock->ptp_info, &ts, NULL);
	ts_next_sec(&ts);
	target_ns = timespec64_to_ns(&ts);

	return find_target_cycles(clock->mdev, target_ns);
}

static u64 pps_perout_real_time(struct mlx5_clock *clock)
{
	struct timespec64 ts;

	mlx5_ptp_real_time_gettimex64(&clock->ptp_info, &ts, NULL);
	ts_next_sec(&ts);

	return perout_conf_real_time(ts.tv_sec, ts.tv_nsec);
}

static int mlx5_pps_event(struct notifier_block *nb,
			  unsigned long type, void *data)
{
	struct mlx5_clock *clock = mlx5_nb_cof(nb, struct mlx5_clock, pps_nb);
	struct mlx5_core_dev *mdev = clock->mdev;
	struct ptp_clock_event ptp_event;
	struct mlx5_eqe *eqe = data;
	int pin = eqe->data.pps.pin;
	unsigned long flags;
	u64 timestamp, ns;

	switch (clock->ptp_info.pin_config[pin].func) {
	case PTP_PF_EXTTS:
		ptp_event.index = pin;
		timestamp = be64_to_cpu(eqe->data.pps.time_stamp);
		ptp_event.timestamp = mlx5_timestamp_to_ns(clock, timestamp);
		if (clock->pps_info.enabled) {
			ptp_event.type = PTP_CLOCK_PPSUSR;
			ptp_event.pps_times.ts_real =
					ns_to_timespec64(ptp_event.timestamp);
		} else {
			ptp_event.type = PTP_CLOCK_EXTTS;
		}
		/* TODOL clock->ptp can be NULL if ptp_clock_register failes */
		ptp_clock_event(clock->ptp, &ptp_event);
		break;
	case PTP_PF_PEROUT:
		ns = REAL_TIME_MODE(clock) ?
		     pps_perout_real_time(clock) :
		     pps_perout_internal_timer(clock);
		write_seqlock_irqsave(&clock->lock, flags);
		clock->pps_info.start[pin] = ns;
		write_sequnlock_irqrestore(&clock->lock, flags);
		schedule_work(&clock->pps_info.out_work);
		break;
	default:
		mlx5_core_err(mdev, " Unhandled clock PPS event, func %d\n",
			      clock->ptp_info.pin_config[pin].func);
	}

	return NOTIFY_OK;
}

static ktime_t mlx5_timecounter_cyc2time(struct mlx5_clock *clock,
					 u64 timestamp)
{
	unsigned int seq;
	u64 nsec;

	do {
		seq = read_seqbegin(&clock->lock);
		nsec = timecounter_cyc2time(&clock->tc, timestamp);
	} while (read_seqretry(&clock->lock, seq));

	return ns_to_ktime(nsec);
}

static ktime_t mlx5_cyc2time(struct mlx5_clock *clock, u64 timestamp)
{
	u64 time = REAL_TIME_TO_NS(timestamp >> 32, timestamp & 0xFFFFFFFF);

	return ns_to_ktime(time);
}

ktime_t mlx5_timestamp_to_ns(struct mlx5_clock *clock, u64 timestamp)
{
	return INDIRECT_CALL_2(clock->cyc2time, mlx5_timecounter_cyc2time,
			       mlx5_cyc2time, clock, timestamp);
}

static void mlx5_init_time(struct mlx5_core_dev *mdev)
{
	struct mlx5_clock *clock = &mdev->clock;
	u32 dev_freq;

	clock->mdev = mdev;
	seqlock_init(&clock->lock);
	if (REAL_TIME_MODE(clock)) {
		struct timespec64 ts;

		ktime_get_real_ts64(&ts);
		mlx5_ptp_real_time_settime(&clock->ptp_info, &ts);
		return;
	}
	dev_freq = MLX5_CAP_GEN(mdev, device_frequency_khz);
	clock->cycles.read = read_internal_timer;
	clock->cycles.shift = MLX5_CYCLES_SHIFT;
	clock->cycles.mult = clocksource_khz2mult(dev_freq,
						  clock->cycles.shift);
	clock->nominal_c_mult = clock->cycles.mult;
	clock->cycles.mask = CLOCKSOURCE_MASK(41);

	timecounter_init(&clock->tc, &clock->cycles,
			 ktime_to_ns(ktime_get_real()));
}

static void mlx5_init_overflow_period(struct mlx5_clock *clock)
{
	struct mlx5_ib_clock_info *clock_info = clock->mdev->clock_info;
	u64 overflow_cycles;
	u64 frac = 0;
	u64 ns;

	if (REAL_TIME_MODE(clock))
		return;

	/* Calculate period in seconds to call the overflow watchdog - to make
	 * sure counter is checked at least twice every wrap around.
	 * The period is calculated as the minimum between max HW cycles count
	 * (The clock source mask) and max amount of cycles that can be
	 * multiplied by clock multiplier where the result doesn't exceed
	 * 64bits.
	 */
	overflow_cycles = div64_u64(~0ULL >> 1, clock->cycles.mult);
	overflow_cycles = min(overflow_cycles, div_u64(clock->cycles.mask, 3));

	ns = cyclecounter_cyc2ns(&clock->cycles, overflow_cycles,
				 frac, &frac);
	do_div(ns, NSEC_PER_SEC / HZ);
	clock->overflow_period = ns;

	INIT_DELAYED_WORK(&clock->overflow_work, mlx5_timestamp_overflow);
	if (clock->overflow_period)
		schedule_delayed_work(&clock->overflow_work, 0);
	else
		mlx5_core_warn(clock->mdev,
			       "invalid overflow period, overflow_work is not scheduled\n");

	if (clock_info)
		clock_info->overflow_period = clock->overflow_period;
}

static void mlx5_init_clock_info(struct mlx5_core_dev *mdev)
{
	struct mlx5_clock *clock = &mdev->clock;
	struct mlx5_ib_clock_info *info;

	if (REAL_TIME_MODE(clock))
		return;

	mdev->clock_info = (struct mlx5_ib_clock_info *)get_zeroed_page(GFP_KERNEL);
	if (!mdev->clock_info)
		return;

	info = mdev->clock_info;

	info->nsec = clock->tc.nsec;
	info->cycles = clock->tc.cycle_last;
	info->mask = clock->cycles.mask;
	info->mult = clock->nominal_c_mult;
	info->shift = clock->cycles.shift;
	info->frac = clock->tc.frac;
}

void mlx5_init_clock(struct mlx5_core_dev *mdev)
{
	struct mlx5_clock *clock = &mdev->clock;

	if (!MLX5_CAP_GEN(mdev, device_frequency_khz)) {
		mlx5_core_warn(mdev, "invalid device_frequency_khz, aborting HW clock init\n");
		return;
	}

	mlx5_get_mtutc_caps(mdev);
	clock->addr_h = REAL_TIME_MODE(clock) ? &mdev->iseg->real_time_h :
						&mdev->iseg->internal_timer_h;
	clock->addr_l = REAL_TIME_MODE(clock) ? &mdev->iseg->real_time_l :
						&mdev->iseg->internal_timer_l;

	mlx5_init_time(mdev);
	mlx5_init_clock_info(mdev);
	mlx5_init_overflow_period(clock);
	clock->cyc2time = REAL_TIME_MODE(clock) ?
			  mlx5_cyc2time : mlx5_timecounter_cyc2time;
	INIT_WORK(&clock->pps_info.out_work, mlx5_pps_out);

	/* Configure the PHC */
	clock->ptp_info = REAL_TIME_MODE(clock) ?
			  mlx5_ptp_real_time_clock_info :
			  mlx5_ptp_clock_info;

	/* Initialize 1PPS data structures */
	if (MLX5_PPS_CAP(mdev))
		mlx5_get_pps_caps(mdev);
	if (clock->ptp_info.n_pins)
		mlx5_init_pin_config(clock);

	clock->ptp = ptp_clock_register(&clock->ptp_info,
					&mdev->pdev->dev);
	if (IS_ERR(clock->ptp)) {
		mlx5_core_warn(mdev, "ptp_clock_register failed %ld\n",
			       PTR_ERR(clock->ptp));
		clock->ptp = NULL;
	}

	MLX5_NB_INIT(&clock->pps_nb, mlx5_pps_event, PPS_EVENT);
	mlx5_eq_notifier_register(mdev, &clock->pps_nb);
}

void mlx5_cleanup_clock(struct mlx5_core_dev *mdev)
{
	struct mlx5_clock *clock = &mdev->clock;

	if (!MLX5_CAP_GEN(mdev, device_frequency_khz))
		return;

	mlx5_eq_notifier_unregister(mdev, &clock->pps_nb);
	if (clock->ptp) {
		ptp_clock_unregister(clock->ptp);
		clock->ptp = NULL;
	}

	cancel_work_sync(&clock->pps_info.out_work);
	if (!REAL_TIME_MODE(clock))
		cancel_delayed_work_sync(&clock->overflow_work);

	if (mdev->clock_info) {
		free_page((unsigned long)mdev->clock_info);
		mdev->clock_info = NULL;
	}

	kfree(clock->ptp_info.pin_config);
}
