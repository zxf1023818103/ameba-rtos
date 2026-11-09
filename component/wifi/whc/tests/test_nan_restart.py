#!/usr/bin/env python3
"""Validate the actual restart hook's activation and no-op guards."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class RestartTest(unittest.TestCase):
    def test_only_successfully_initialized_inactive_timer_is_armed(self):
        source = Path(__file__).resolve().parents[1] / 'whc_dev/whc_dev_nan_restart_fix.c'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'fix.c').write_text(source.read_text())
            (root / 'whc_dev.h').write_text('''#include <stdint.h>
#include <string.h>
#include <assert.h>
typedef void *rtos_timer_t;
uint32_t rtos_timer_is_timer_active(rtos_timer_t);
#define RTK_LOGS(...) ((void)0)
''')
            (root / 'test.c').write_text('''#include "fix.c"
static uint8_t storage[2360];
uint8_t *g_nanpriv = storage;
static uint8_t control[1776];
uint8_t *g_nanctrl;
static unsigned active, armed;
static unsigned events[3], event_count;
uint32_t rtw_nan_event_enqueue(uint32_t event, const void *data, uint32_t len) {
    assert(!data && !len && event_count < 3); events[event_count++] = event; return 1;
}
uint32_t rtos_timer_is_timer_active(rtos_timer_t t) { assert(t == (void *)123); return active; }
void rtw_nan_dw_timer_reset(uint8_t enable) { assert(enable == 1); ++armed; }
static void start(void) { green2_nan_arm_discovery_timer(); }
int main(void) {
    rtos_timer_t t = (void *)123; memcpy(storage+2268, &t, sizeof(t));
    storage[2350] = 3; start(); assert(armed == 1);
    active = 1; start(); assert(armed == 1);
    active = 0; storage[2350] = 1; start(); assert(armed == 1);
    t = 0; memcpy(storage+2268, &t, sizeof(t)); storage[2350] = 3; start(); assert(armed == 1);
    g_nanpriv = 0; start(); assert(armed == 1);
    g_nanpriv = storage; g_nanctrl = control;
    t = (void *)123; memcpy(storage+2268, &t, sizeof(t));
    storage[6] = 1; active = 1; start(); assert(armed == 1 && !event_count);
    control[1668] = 1; start();
    assert(armed == 2 && event_count == 3 && (storage[2350] & 4));
    assert(events[0] == 21 && events[1] == 11 && events[2] == 5);
    storage[2350] = 1; start(); assert(armed == 2 && event_count == 3);
}
''')
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(root / 'test.c'),
                            '-o', str(root / 'test')], check=True)
            subprocess.run([str(root / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
