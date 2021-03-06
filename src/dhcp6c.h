
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

enum message_type
{
	SOLICIT = 1,
	ADVERTISE = 2,
	REQUEST = 3,
	CONFIRM = 4
};

enum option_code
{
	OPTION_CLIENTID = 1,
	OPTION_SERVERID = 2,
	OPTION_IA_NA = 3,
	OPTION_IA_TA = 4,
	OPTION_IAADDR = 5,
	OPTION_ORO = 6,
	OPTION_PREFERENCE = 7,
	OPTION_ELAPSED_TIME = 8,
	OPTION_RELAY_MSG = 9,
	OPTION_AUTH = 11,
	OPTION_UNICAST = 12,
	OPTION_STATUS_CODE = 13,
	OPTION_RAPID_COMMIT = 14,
	OPTION_USER_CLASS = 15,
	OPTION_VENDOR_CLASS = 16,
	OPTION_VENDOR_OPTS = 17,
	OPTION_INTERFACE_ID = 18,
	OPTION_RECONF_MSG = 19,
	OPTION_RECONF_ACCEP = 20,
	OPTION_SIP_SERVER_D = 21,
	OPTION_SIP_SERVER_A = 22,
	OPTION_DNS_SERVERS = 23,
	OPTION_DOMAIN_LIST = 24,
	OPTION_IA_PD = 25,
	OPTION_IAPREFIX = 26,
	OPTION_NIS_SERVERS = 27,
	OPTION_NISP_SERVERS = 28,
	OPTION_NIS_DOMAIN_NAME = 29,
	OPTION_NISP_DOMAIN_NAME = 30,
	OPTION_SNTP_SERVERS = 31,
	OPTION_INFORMATION_REFRESH_TIME = 32,
	OPTION_BCMCS_SERVER_D = 33,
	OPTION_BCMCS_SERVER_A = 34,
	OPTION_GEOCONF_CIVIC = 36,
	OPTION_REMOTE_ID = 37,
	OPTION_SUBSCRIBER_ID = 38,
	OPTION_CLIENT_FQDN = 39,
	OPTION_PANA_AGENT = 40
};

struct dhcpv6_soliocit
{
	uint8_t message_type;
	uint8_t trans_ID[0];
};
struct dhcpv6_option
{
	uint16_t option;
	uint16_t len;
	uint8_t value[0];
};
struct dhcpv6_domain_name
{
	uint8_t option;
	uint8_t len;
	uint8_t name[0];
};
struct dhcpv6_IA_ID
{
	uint32_t iaid;
	uint32_t t1;
	uint32_t t2;
};

struct dhcpv6_vendor_class
{
	uint32_t enterprise_id;
	uint16_t len;
	uint8_t data[0];
} __attribute__((packed));
;
