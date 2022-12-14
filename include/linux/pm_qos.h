#ifndef _COMPAT_LINUX_PM_QOS_H
#define _COMPAT_LINUX_PM_QOS_H 1

#ifdef CONFIG_COMPAT_PM_QOS_V2
#include_next <linux/pm_qos.h>
#else /* CONFIG_COMPAT_PM_QOS_V2 */
#include <linux/pm_qos_params.h>
#ifdef CONFIG_COMPAT_PM_QOS_V1
#define pm_qos_request pm_qos_request_list
#else /* CONFIG_COMPAT_PM_QOS_V1 */

struct pm_qos_request {
	u32 qos;
	void *request;
};

#define pm_qos_request(_qos) pm_qos_requirement(_qos)
#define pm_qos_add_request(_req, _class, _value) do {			\
	(_req)->request = #_req;					\
	(_req)->qos = _class;						\
	pm_qos_add_requirement((_class), (_req)->request, (_value));	\
} while (0)

#define pm_qos_update_request(_req, _value)				\
	pm_qos_update_requirement((_req)->qos, (_req)->request, (_value))

#define pm_qos_remove_request(_req)					\
	pm_qos_remove_requirement((_req)->qos, (_req)->request)

#endif /* CONFIG_COMPAT_PM_QOS_V1 */
#endif /* CONFIG_COMPAT_PM_QOS_V2 */
#endif	/* _COMPAT_LINUX_PM_QOS_H */
