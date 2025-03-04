#ifndef __AIIO_LOG_H__
#define __AIIO_LOG_H__

#include <stdio.h>

#define aiio_log_a(fmt, arg...)                  printf(fmt, ##arg)
#define aiio_log_e(fmt, arg...)                  printf(fmt, ##arg)
#define aiio_log_w(fmt, arg...)                  printf(fmt, ##arg)
#define aiio_log_i(fmt, arg...)                  printf(fmt, ##arg)
#define aiio_log_d(fmt, arg...)                  ((void)0)
#define aiio_log_v(fmt, arg...)                  ((void)0)

#define aiio_assert(EXPR)			((void)0);

#endif
