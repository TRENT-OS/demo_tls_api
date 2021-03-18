/*
 * UART API
 *
 *  Copyright (C) 2019, HENSOLDT Cyber GmbH
 */

#pragma once

void Uart_enable();
void Uart_putChar(char byte);
char Uart_getChar();
