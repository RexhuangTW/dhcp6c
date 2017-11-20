#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "dhcp6c.h"

#define DST_PORT 546
#define SRC_PORT 547
#define DHCPV6_MUTICAST_ADDRESS "ff02::1:2"


int add_option(uint8_t *dest, enum option_code opt_code, uint16_t len, uint8_t *data)
{
	struct dhcpv6_option *opt_packet = (struct dhcpv6_option *)dest;

	opt_packet->option = htons(opt_code);
	opt_packet->len = htons(len);
	memcpy(opt_packet->value, data, len);

	return (sizeof(struct dhcpv6_option) + len);
}
int add_message(uint8_t *dest, enum message_type msg_type, uint16_t len, uint8_t *data)
{
	struct dhcpv6_soliocit *opt_packet = (struct dhcpv6_soliocit *)dest;

	opt_packet->message_type = msg_type;
	memcpy(opt_packet->trans_ID, data, len);

	return (sizeof(struct dhcpv6_soliocit) + len);
}
int add_domain_name_packet(uint8_t *dest, uint8_t option, uint8_t len, uint8_t *name)
{
	struct dhcpv6_domain_name *do_name = (struct dhcpv6_domain_name *)dest;

	do_name->option = option;
	do_name->len = len;
	memcpy(do_name->name, name, len);

	return (sizeof(struct dhcpv6_domain_name) + len);
}
void int2hex(uint8_t *dest, int num)
{
	dest[1] = num & 0xFF;		 // low byte
	dest[0] = (num >> 8) & 0xFF; // high byte
}

int main(int argc, char *argv[])
{
	struct sockaddr_in6 addr = {0};
	struct sockaddr_in6 client_addr = {0};
	struct in_addr ipaddr = {0};
	struct dhcpv6_IA_ID ia_id_v = {0};
	int fd, cnt,i;
	uint8_t buf[1024] = {0};
	uint8_t sub_value[521] = {0};
	size_t offest = 0, sub_offest = 0;
	uint8_t soliocit[3] = {0};
	uint8_t duid[18] = {0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
						0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
	uint8_t req_opt[4] = {24,23,17,39};
	uint8_t elapsed_time[2];
	uint8_t *client_name = "Rex_test";
	uint8_t *vend_class_data = "MSFT 5.0";
	int urandom_fd = -1;
	uint32_t iaid = 0x0894e979;
	uint32_t enterprise_id = 311;
	uint16_t t1 = 0, t2 = 0;
	int delay_time = 300;

	/* create what looks like an ordinary UDP socket */
	if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
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

	if (bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
	{
		perror("bind");
		exit(1);
	}
	/* Add message type */
	urandom_fd = open("/dev/urandom", O_RDONLY);
	read(urandom_fd, soliocit, sizeof(soliocit));
	close(urandom_fd);
	offest += add_message(buf + offest, SOLICIT, sizeof(soliocit), soliocit);

	/* Addoption */

	/* Elapsedtime */
	int2hex(elapsed_time, delay_time);
	offest += add_option(buf + offest, OPTION_ELAPSED_TIME, sizeof(elapsed_time), elapsed_time);

	/* Client Identifier */
	offest += add_option(buf + offest, OPTION_CLIENTID, sizeof(duid), duid);

	/* IA_NA */
	ia_id_v.iaid = htonl(iaid);
	ia_id_v.t1 = htons(t1);
	ia_id_v.t2 = htons(t2);
	offest += add_option(buf + offest, OPTION_IA_NA, sizeof(ia_id_v), (uint8_t *)&ia_id_v);

	/* Fully Qualified Domain Name */
	sub_offest += add_domain_name_packet(sub_value, 0x00, strlen(client_name), client_name);
	offest += add_option(buf + offest, OPTION_CLIENT_FQDN, sub_offest, sub_value);

	/* Vendor Class */
	struct dhcpv6_vendor_class *vend_class = malloc(sizeof(struct dhcpv6_vendor_class) + strlen(vend_class_data));
	vend_class->enterprise_id = htonl(enterprise_id);
	vend_class->len = strlen(vend_class_data);
	memcpy(vend_class->data, vend_class_data, vend_class->len);
	offest += add_option(buf + offest, OPTION_VENDOR_CLASS, sizeof(struct dhcpv6_vendor_class) + strlen(vend_class_data), vend_class);

	/* Option Request */
	memset(sub_value,0x00,sizeof(sub_value));
	for(i =0; i<sizeof(req_opt); i++)
	{
		sub_value[i*2] = (req_opt[i]>>8) & 0xFF;
		sub_value[i*2+1] = req_opt[i] & 0xFF;
	}

	offest += add_option(buf + offest, OPTION_ORO, sizeof(req_opt)*2, sub_value);

	
	if (sendto(fd, buf, offest, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("sendto");
		exit(1);
	}

	free(vend_class);

	return 0;
}
