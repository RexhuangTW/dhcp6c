#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "dhcp6c.h"

#define	DST_PORT 547
#define	SRC_PORT 546
#define	DHCPV6_MUTICAST_ADDRESS	"ff02::1:2"

int add_option(uint8_t *dest, enum option_code opt_code, uint16_t len, uint8_t *data)
{
	struct dhcpv6_option *opt_packet = (struct dhcpv6_option*)dest;

	opt_packet->option = htons(opt_code);
	opt_packet->len = htons(len);
	memcpy(opt_packet->value, data, len);

	return(sizeof(struct dhcpv6_option) + len);
}
int add_message(uint8_t *dest, enum message_type msg_type, uint16_t len, uint8_t *data)
{
	struct dhcpv6_soliocit *opt_packet = (struct dhcpv6_soliocit*)dest;

	opt_packet->message_type = msg_type;
	memcpy(opt_packet->trans_ID, data, len);

	return(sizeof(struct dhcpv6_soliocit) + len);	
}
int add_domain_name_packet(uint8_t *dest, uint8_t option, uint8_t len, uint8_t *name)
{
	struct dhcpv6_domain_name *do_name = (struct dhcpv6_domain_name*)dest;

	do_name->option = option;
	do_name->len = len;
	memcpy(do_name->name, name, len);

	return(sizeof(struct dhcpv6_domain_name) + len);
}
void int2hex(uint8_t *dest, int num)
{
	dest[1] = num & 0xFF;		// low byte
	dest[0] = (num >> 8) & 0xFF;	// high byte
}

int main(int argc, char *argv[])
{
	struct sockaddr_in6 addr = {0};
	struct sockaddr_in6 client_addr = {0};
	struct in_addr ipaddr = {0};
	struct dhcpv6_IA_ID ia_id_v;
	int fd, cnt;
	uint8_t buf[1024] = {0};
	uint8_t sub_value[521] = {0};
	size_t offest=0, sub_offest=0;
	uint8_t soliocit[3] = {0xAA, 0xAA, 0xAA};
	uint8_t duid[18] = {0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
	uint8_t req_opt[10] = {0x00, 0x17, 0x00, 0x18, 0x00, 0x17, 0x00, 0x18, 0x00, 0x01};
	uint8_t elapsed_time[2];
	uint8_t client_name[8]={'R','e','x','_','t','e','s','t'};

	/* create what looks like an ordinary UDP socket */
	if(( fd = socket(AF_INET6, SOCK_DGRAM, 0))<0)
	{
		perror("socket");
		exit(1);
	}
	/* setupdestinationaddress */
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(DST_PORT);
	inet_pton(AF_INET6, DHCPV6_MUTICAST_ADDRESS, &addr.sin6_addr);
	addr.sin6_flowinfo = 0;

	// Configure IPv6-options
	int val = 1;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val));	
	client_addr.sin6_family = AF_INET6;
	client_addr.sin6_port = htons(SRC_PORT);

	if(bind(fd, (struct sockaddr*)&client_addr, sizeof(client_addr))<0)
	{
		perror("bind");
		exit(1);
	}
	/* Add message type */
	offest += add_message(buf + offest, SOLICIT, sizeof(soliocit), soliocit);

	/* Addoption */

	/* Elapsedtime */
	int2hex(elapsed_time, 300);
	offest += add_option( buf + offest, OPTION_ELAPSED_TIME, sizeof(elapsed_time), elapsed_time);
	
	/* Client Identifier */
	offest += add_option( buf + offest, OPTION_CLIENTID, sizeof(duid), duid);

	/* IA_NA */
	ia_id_v.iaid = 0x79e99408;
	ia_id_v.t1 = htons(0);
	ia_id_v.t2 = htons(0);
	offest += add_option( buf + offest, OPTION_IA_NA, sizeof(ia_id_v),(uint8_t *)&ia_id_v);
	
	/*Fully Qualified Domain Name*/
	sub_offest += add_domain_name_packet(sub_value, 0x00,sizeof(client_name), client_name);
	offest += add_option( buf + offest, OPTION_CLIENT_FQDN, sub_offest, sub_value);
	
	/*Option Request*/
	offest += add_option( buf + offest, OPTION_ORO, sizeof(req_opt), req_opt);

	if(sendto( fd, buf, offest, 0, (struct sockaddr*)&addr, sizeof(addr))<0)
	{
		perror("sendto");
		exit(1);
	}

	return 0;
}


