// SPDX-License-Identifier: GPL-2.0
/*
 * The guest's real-time clock, /dev/rtc0.  Besides hwclock, the alarm
 * clocks (CLOCK_REALTIME_ALARM and CLOCK_BOOTTIME_ALARM) need it: without
 * an RTC that has alarms and may wake the system, only timerfd works on
 * them, and clock_gettime(), clock_nanosleep() and POSIX timers fail.
 *
 * It reads the host's wall clock (L4H_HC_GET_TIME: the machine RTC at host
 * boot plus the TSC time since) plus an offset that setting it changes.
 * The offset is the guest's own and lasts until the guest stops: the
 * machine RTC is dom0's to set, with l4hctl rtc-set.  An alarm is an
 * hrtimer, on the same TSC.
 */
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/rtc.h>
#include <l4h_sys.h>

struct l4h_rtc {
	struct rtc_device *rtc;
	struct hrtimer timer;
	s64 offset;		/* ns added to the host's clock */
	time64_t alarm;		/* RTC seconds */
	bool alarm_on;
};

static s64 l4h_rtc_ns(struct l4h_rtc *p)
{
	unsigned long mr = 0;

	return (s64)l4h_hypercall(L4H_HC_GET_TIME, &mr, 0, 1) + p->offset;
}

/* The rtc core calls the ops below with its ops_lock held. */
static void l4h_rtc_arm(struct l4h_rtc *p)
{
	s64 delta;

	hrtimer_cancel(&p->timer);
	if (!p->alarm_on)
		return;
	delta = p->alarm * NSEC_PER_SEC - l4h_rtc_ns(p);
	hrtimer_start(&p->timer, ns_to_ktime(max_t(s64, delta, 0)), HRTIMER_MODE_REL);
}

static enum hrtimer_restart l4h_rtc_fire(struct hrtimer *t)
{
	struct l4h_rtc *p = container_of(t, struct l4h_rtc, timer);

	rtc_update_irq(p->rtc, 1, RTC_IRQF | RTC_AF);
	return HRTIMER_NORESTART;
}

static int l4h_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct l4h_rtc *p = dev_get_drvdata(dev);

	rtc_time64_to_tm(div_s64(l4h_rtc_ns(p), NSEC_PER_SEC), tm);
	return 0;
}

static int l4h_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct l4h_rtc *p = dev_get_drvdata(dev);
	unsigned long mr = 0;

	p->offset = rtc_tm_to_time64(tm) * NSEC_PER_SEC -
		    (s64)l4h_hypercall(L4H_HC_GET_TIME, &mr, 0, 1);
	l4h_rtc_arm(p);
	return 0;
}

static int l4h_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct l4h_rtc *p = dev_get_drvdata(dev);

	rtc_time64_to_tm(p->alarm, &alrm->time);
	alrm->enabled = p->alarm_on;
	return 0;
}

static int l4h_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct l4h_rtc *p = dev_get_drvdata(dev);

	p->alarm = rtc_tm_to_time64(&alrm->time);
	p->alarm_on = alrm->enabled;
	l4h_rtc_arm(p);
	return 0;
}

static int l4h_rtc_alarm_irq_enable(struct device *dev, unsigned int enabled)
{
	struct l4h_rtc *p = dev_get_drvdata(dev);

	p->alarm_on = enabled;
	l4h_rtc_arm(p);
	return 0;
}

static const struct rtc_class_ops l4h_rtc_ops = {
	.read_time = l4h_rtc_read_time,
	.set_time = l4h_rtc_set_time,
	.read_alarm = l4h_rtc_read_alarm,
	.set_alarm = l4h_rtc_set_alarm,
	.alarm_irq_enable = l4h_rtc_alarm_irq_enable,
};

static int __init l4h_rtc_probe(struct platform_device *pdev)
{
	struct l4h_rtc *p;

	p = devm_kzalloc(&pdev->dev, sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->rtc = devm_rtc_allocate_device(&pdev->dev);
	if (IS_ERR(p->rtc))
		return PTR_ERR(p->rtc);
	hrtimer_setup(&p->timer, l4h_rtc_fire, CLOCK_BOOTTIME, HRTIMER_MODE_REL);
	platform_set_drvdata(pdev, p);
	p->rtc->ops = &l4h_rtc_ops;
	p->rtc->range_max = RTC_TIMESTAMP_END_9999;
	/* Alarm timers use only an RTC that may wake the system. */
	device_init_wakeup(&pdev->dev, true);
	return devm_rtc_register_device(p->rtc);
}

static struct platform_driver l4h_rtc_driver = {
	.driver = {
		.name = "rtc-l4h",
		.suppress_bind_attrs = true,
	},
};

static int __init l4h_rtc_init(void)
{
	struct platform_device *pdev;
	int err;

	pdev = platform_device_register_simple("rtc-l4h", PLATFORM_DEVID_NONE, NULL, 0);
	if (IS_ERR(pdev))
		return PTR_ERR(pdev);
	err = platform_driver_probe(&l4h_rtc_driver, l4h_rtc_probe);
	if (err)
		platform_device_unregister(pdev);
	return err;
}
device_initcall(l4h_rtc_init);
