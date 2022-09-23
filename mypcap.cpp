#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include "mypcap.h"
#define ip_start 14
#define tcp_start 20

void print_mac(const u_char* print_array)
{
	uint8_t i;
	for(i=0;i<5;i++)
		printf("%02x:",*(print_array+i));
	printf("%02x\n",*(print_array+i));
	return;
}
void print_ip(const u_char* print_array)
{
	int8_t i;
	for(i=0;i<3;i++)
		printf("%d.",*(print_array+i));
	printf("%d\n",*(print_array+i));
	return;
}
void print_tcp(const u_char* print_array)
{
      	uint16_t temp;
	memcpy(&temp,print_array,2);
	temp = ntohs(temp);
	printf("%u\n",temp);
}
uint16_t mymin(uint16_t a, uint16_t b)
{
	return a>b?b:a;
}
void print_data(const u_char* packet, uint16_t size)
{
	uint8_t i;
	for(i=0;i<size;i++)
		printf("%02x",*(packet+i));
	printf("\n");
	return;
}
void print_pcap(const u_char* packet)
{	
	uint16_t check_upper_ip;
	uint8_t check_upper_tcp;
	uint8_t data_start;
	uint16_t tcp_size;	

	memcpy(&check_upper_ip,&packet[12],2);
	check_upper_ip = ntohs(check_upper_ip);
	if(check_upper_ip != 0x0800)
		return;
	
	memcpy(&check_upper_tcp,&packet[ip_start+9],1);
	if(check_upper_tcp != 0x6)
		return;

	printf("mac src : ");
	print_mac(packet+6);
	printf("mac des : ");
	print_mac(packet);

	printf("ip src : ");
	print_ip(packet+ip_start-1+13);
	printf("ip des : ");
	print_ip(packet+ip_start-1+17);

	printf("tcp src : ");
	print_tcp(packet+ip_start+tcp_start-1+1);
	printf("tcp des : ");
	print_tcp(packet+ip_start+tcp_start-1+3);
	
	data_start = *(packet+ip_start+tcp_start-1+13)>>2;
	memcpy(&tcp_size,packet+ip_start+tcp_start-1+15,2);
	tcp_size = ntohs(tcp_size);

	print_data(packet+ip_start+tcp_start+data_start-1,mymin(tcp_size-data_start,10));
	printf("\n");
	return ;
}
