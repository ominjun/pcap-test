#include <stdint.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#pragma once

void print_mac(const u_char* print_array);
void print_ip(const u_char* print_array);
void print_tcp(const u_char* print_array);
uint16_t mymin(uint16_t a, uint16_t b);
void print_data(const u_char* packet, uint16_t size);
void print_pcap(const u_char* packet);
