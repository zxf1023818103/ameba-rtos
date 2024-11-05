/**
 * Copyright (c) 2015 - present LibDriver All rights reserved
 * 
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. 
 *
 * @file      driver_at24cxx_interface_template.c
 * @brief     driver at24cxx interface template source file
 * @version   2.0.0
 * @author    Shifeng Li
 * @date      2021-02-17
 *
 * <h3>history</h3>
 * <table>
 * <tr><th>Date        <th>Version  <th>Author      <th>Description
 * <tr><td>2021/02/17  <td>2.0      <td>Shifeng Li  <td>format the code
 * <tr><td>2020/10/15  <td>1.0      <td>Shifeng Li  <td>first upload
 * </table>
 */

#include "driver_at24cxx_interface.h"
#include "i2c_api.h"
#include "i2c_ex_api.h"
#include "example_mofang_v10.h"
#include "os_wrapper_time.h"
#include <stdio.h>

static i2c_t i2c0;

/**
 * @brief  interface iic bus init
 * @return status code
 *         - 0 success
 *         - 1 iic init failed
 * @note   none
 */
uint8_t at24cxx_interface_iic_init(void)
{
    memset(&i2c0, 0, sizeof(i2c_t));
    i2c_init(&i2c0, I2C0_SDA, I2C0_SCL);
    i2c_frequency(&i2c0, I2C0_FREQ);
    return 0;
}

/**
 * @brief  interface iic bus deinit
 * @return status code
 *         - 0 success
 *         - 1 iic deinit failed
 * @note   none
 */
uint8_t at24cxx_interface_iic_deinit(void)
{
    return 0;
}

/**
 * @brief      interface iic bus read
 * @param[in]  addr is the iic device write address
 * @param[in]  reg is the iic register address
 * @param[out] *buf points to a data buffer
 * @param[in]  len is the length of the data buffer
 * @return     status code
 *             - 0 success
 *             - 1 read failed
 * @note       none
 */
uint8_t at24cxx_interface_iic_read(uint8_t addr, uint8_t reg, uint8_t *buf, uint16_t len)
{
    addr >>= 1;
    return ((i2c_write(&i2c0, addr, (const char*)&reg, 1, 0) == 1) && (i2c_read(&i2c0, addr, (char*)buf, len, 1) == len)) ? 0 : 1;
}

/**
 * @brief     interface iic bus write
 * @param[in] addr is the iic device write address
 * @param[in] reg is the iic register address
 * @param[in] *buf points to a data buffer
 * @param[in] len is the length of the data buffer
 * @return    status code
 *            - 0 success
 *            - 1 write failed
 * @note      none
 */
uint8_t at24cxx_interface_iic_write(uint8_t addr, uint8_t reg, uint8_t *buf, uint16_t len)
{
    addr >>= 1;
    return ((i2c_write(&i2c0, addr, (const char*)&reg, 1, 0) == 1) && (i2c_write(&i2c0, addr, (char*)buf, len, 1) == len)) ? 0 : 1;
}

/**
 * @brief      interface iic bus read with 16 bits register address
 * @param[in]  addr is the iic device write address
 * @param[in]  reg is the iic register address
 * @param[out] *buf points to a data buffer
 * @param[in]  len is the length of the data buffer
 * @return     status code
 *             - 0 success
 *             - 1 read failed
 * @note       none
 */
uint8_t at24cxx_interface_iic_read_address16(uint8_t addr, uint16_t reg, uint8_t *buf, uint16_t len)
{
    addr >>= 1;
    char reg16[2] = { (char)(reg >> 8), (char)reg };
    return ((i2c_write(&i2c0, addr, reg16, 2, 0) == 2) && (i2c_read(&i2c0, addr, (char*)buf, len, 1) == len)) ? 0 : 1;
}

/**
 * @brief     interface iic bus write with 16 bits register address
 * @param[in] addr is the iic device write address
 * @param[in] reg is the iic register address
 * @param[in] *buf points to a data buffer
 * @param[in] len is the length of the data buffer
 * @return    status code
 *            - 0 success
 *            - 1 write failed
 * @note      none
 */
uint8_t at24cxx_interface_iic_write_address16(uint8_t addr, uint16_t reg, uint8_t *buf, uint16_t len)
{
    addr >>= 1;
    char reg16[2] = { (char)(reg >> 8), (char)reg };
    return ((i2c_write(&i2c0, addr, reg16, 2, 0) == 2) && (i2c_write(&i2c0, addr, (char*)buf, len, 1) == len)) ? 0 : 1;
}

/**
 * @brief     interface delay ms
 * @param[in] ms
 * @note      none
 */
void at24cxx_interface_delay_ms(uint32_t ms)
{
    rtos_time_delay_ms(ms);
}

/**
 * @brief     interface print format data
 * @param[in] fmt is the format data
 * @note      none
 */
void at24cxx_interface_debug_print(const char *const fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
