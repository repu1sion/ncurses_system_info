/* nsi */
/* gcc nsi.c -lncurses -o nsi */
/* /bin/sh -c /bin/login */

//-------------------------------------- headers ----------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* for hostname */
#include <sys/types.h>  /* below 5 for ip addr */
#include <sys/stat.h>     /* for stat() */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h> /* for AF_INET, AF_INET6 families */
#include <net/if.h>
#include <ifaddrs.h> /* for getifaddrs() */
#include <arpa/inet.h>
#include <netdb.h>  /* for getnameinfo() */
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/vfs.h> /* for disk usage info */
#include <signal.h> /* for signals */
#include <ncurses.h>

//-------------------------------------- defines  ----------------------
//#define DEBUG

#ifdef DEBUG
 #define debug(x...) mvprintw(x)
#else
 #define debug(x...)
#endif

#define VERSION "1.04"

#define APP_NAME "[nsi] "
#define APP_ERROR "[boot_menu error] "

/* system */
#define KB 1024
#define MB (1024*1024)
#define HOSTNAME_SIZE 60
#define TIME_TO_REFRESH 1 /* in seconds */

/* config */
#define CONFIG_NAME "/etc/boot-menu.txt"
#define CONFIG_LINES_NUM 9
#define CONFIG_LINE_LENGTH 36

/* boot_info */
#define INFO_NAME "/etc/boot-info.txt"
#define INFO_LINES_NUM 20
#define INFO_LINES_NUM_MIN 5
#define INFO_LINE_LENGTH 70
#define INFO_LINE_LENGTH_MIN 30

/* exe */
#define F1_EXE "/bin/login"
#define F2_EXE "/sbin/lf_setup"
#define F3_EXE "/sbin/lf_support"
#define SHUTDOWN_EXE "/sbin/poweroff"
#define REBOOT_EXE "/sbin/reboot"

/* network */
#define DEF_INTF_NAME "eth0"
//#define DEF_INTF_NAME "wlan0"
#define NET_INTF_NUM 1   /* will have only eth0 default */
#define DNS_NUM 2 
#define ADDR_SIZE 16

/* menu */
#define MENU_ITEMS_NUM 2
#define MENU_COL_START 2
#define MENU_ROW_START 3 
#define MENU_ROW_END (term_rows - 3) 

/* info area */
#define INFO_ROW_START 4  /* number of row where info area actually starts */
#define INFO_ROW_END (term_rows - 3)
#define INFO_OFFSET 17 /* for example: HOSTNAME: pulsehouse */

/* bg */
#define BG_END (INFO_ROW_START + 9)

/* focus */
#define FOCUS_SIZE (term_cols/2 -3)

/* bar */
#define BAR_SIZE 33
#define BAR_OFFSET 15  /* horizontal offset from left border */
#define LOAD_FREE_OFFSET 52

/* win_shut */
#define WIN_SHUT_W 30
#define WIN_SHUT_H 5
#define WIN_SHUT_MENU_ITEMS_NUM 3
#define WIN_SHUT_MENU_COL_START 2
#define WIN_SHUT_MENU_ROW_START 1 
#define WIN_SHUT_FOCUS_SIZE (WIN_SHUT_W -2)

/* win_info */
#define WIN_INFO_MENU_COL_START 2
#define WIN_INFO_MENU_ROW_START 1 
//-------------------------------------- new data types  ----------------------
typedef unsigned char u8;

/* state machine depends on current windows */
enum window_t
{
        WIN_MAIN,
	WIN_SHUT,
	WIN_INFO
};

/* cursor. need it for focus */
static struct
{
	int row;
	int col;
} pulse_cur;

/* win_info */
static struct
{
	int w;
	int h;
	int lines;
	int chars;
} win_info;

/* global */
static struct
{
	enum window_t window; /* current window */
	WINDOW *win_shut;
	WINDOW *win_info;
	u8 nologin; /* check file /etc/boot-nologin. 1 if present */
	u8 boot_info; /* 1 if /etc/boot-info.txt is present */
} bnglobal;

/* system */
static struct
{
	char hostname[HOSTNAME_SIZE];
	char cpuload[15];
	int cpu_user;
	int cpu_system;
	int cpu_idle;
	int cpu_total; /* sum of us + sy */
	int mem_total; /* store mem and swap in KB */
	int mem_free;
	int swap_total;
	int swap_free;
	double  disk_root_free;  /* priv user */
	double  disk_root_avail; /* non priv user - show this*/
	double  disk_root_total; /* in KB */
	double  disk_data_free;
	double  disk_data_avail; /* non priv user - show this*/
	double  disk_data_total;
} pulse_sys;

/* keep data about network interface here. NOT USED NOW */
#if 0
static struct
{
	unsigned char name[6]; 
	u8 ip[4];
	u8 mask[4];
	u8 mac[6];
	u8 gateway[4];
	u8 dns[DNS_NUM][4];/* [0]-Primary DNS, then [1],[2] - Secondary DNS */
} pulse_net;
#endif

/* keep data about network interface here. ip, mask etc stored in char */
static struct
{
	unsigned char name[6];
	u8 dhcp_enabled;            // 1 - enabled
	unsigned char ip[ADDR_SIZE]; 
	unsigned char mask[ADDR_SIZE]; 
	unsigned char gateway[ADDR_SIZE]; 
	unsigned char mac[6];       //mac stored in byte format
	unsigned char dns[DNS_NUM][ADDR_SIZE];/* [0]-Primary DNS, then [1],[2] - Secondary DNS */
} pulse_net_str;

//-------------------------------------- prototypes----------------------
void pulse_create_win_info();

//-------------------------------------- variables ----------------------
/* current term */
static int term_rows, term_cols;

/* menu */
static char *menu[MENU_ITEMS_NUM] = {"SYSTEM INFO", "NETWORK INFO"};
static int   menu_cnt = 0;  /* currently selected menu item by cursor */

/* win_shut menu */
static char *win_shut_menu[WIN_SHUT_MENU_ITEMS_NUM] = {"SHUTDOWN", "REBOOT", "CANCEL"};
static int   win_shut_menu_cnt = 0;  /* currently selected menu item by cursor */

/* config lines */
char config_lines[CONFIG_LINES_NUM][CONFIG_LINE_LENGTH] = {0};

/* info lines */
char info_lines[INFO_LINES_NUM][INFO_LINE_LENGTH] = {0};
//-----------------------------init and config functions -----------------------
void pulse_init()
{
#if 0
	memset(&pulse_net, 0x0, sizeof(pulse_net)); 
#endif
	memset(&bnglobal, 0x0, sizeof(bnglobal));
	memset(&win_info, 0x0, sizeof(win_info));
	memset(&pulse_sys, 0x0, sizeof(pulse_sys));
	memset(&pulse_net_str, 0x0, sizeof(pulse_net_str));
	pulse_cur.row = MENU_ROW_START;
	pulse_cur.col = MENU_COL_START;
}

/* SOLID */
void pulse_exit()
{
        endwin(); 
	exit(0);
}

/* If /etc/boot-nologin is present - don't display the F1 login menu */
void pulse_check_nologin()
{
	FILE *f = fopen("/etc/boot-nologin", "r");
	if (f)
	{
		bnglobal.nologin = 1;
		fclose(f);
	}
	else
		bnglobal.nologin = 0;
}

/* If /etc/boot-info.txt is present - launch popup */
void pulse_check_boot_info()
{
	FILE *f = fopen(INFO_NAME, "r");
	char line[INFO_LINE_LENGTH] = {0};
	int lines_cnt = 0; 
	int chars_cnt = 0;
	int current_chars;
	int i;

	if (f)
		bnglobal.boot_info = 1;
	else 
	{
		bnglobal.boot_info = 0;
		return;
	}
	
	memset(info_lines, 0x0, sizeof(info_lines));

	/* read 1 line in every iteration */
	while(fgets(line, sizeof(line), f))
	{
		/* calculate chars per current line. save if its max value */
		current_chars = strlen(line);
		if (chars_cnt < current_chars)
			chars_cnt = current_chars;

		/* copy -1 chars because we want '\0' in the end */
		strncpy(info_lines[lines_cnt], line, INFO_LINE_LENGTH-1);

		/* remove 0xa */
		for (i = 0; i < INFO_LINE_LENGTH; i++)
		{
			if (info_lines[lines_cnt][i] == 0xa)
				info_lines[lines_cnt][i] = 0x0;
		}

		if (++lines_cnt == INFO_LINES_NUM) break;
	}

	/* window should be at least minimal size */
	win_info.lines = (lines_cnt > INFO_LINES_NUM_MIN) ? lines_cnt : INFO_LINES_NUM_MIN;
	win_info.chars = (chars_cnt > INFO_LINE_LENGTH_MIN) ? chars_cnt : INFO_LINE_LENGTH_MIN;
	win_info.h = win_info.lines + 2; /* window size > number of lines and chars */
	win_info.w = win_info.chars + 3;

	fclose(f);
}

/* SOLID */
void pulse_read_config()
{
	FILE *f = fopen(CONFIG_NAME, "r");
	char line[256] = {0};
	int lines_cnt = 0; 
	int i;

	if (!f) 
	{
		//printf("[error] can't open config %s \n", CONFIG_NAME);
		return;
	}

	/* need it if we reread config during program run */	
	memset(config_lines, 0x0, sizeof(config_lines));

	/* read 1 line in every iteration */
	while(fgets(line, sizeof(line), f))
	{
		/* copy -1 chars because we want '\0' in the end */
		strncpy(config_lines[lines_cnt], line, CONFIG_LINE_LENGTH-1);

		/* remove 0xa */
		for (i = 0; i < CONFIG_LINE_LENGTH; i++)
		{
			if (config_lines[lines_cnt][i] == 0xa)
				config_lines[lines_cnt][i] = 0x0;
		}

		if (++lines_cnt == CONFIG_LINES_NUM) break;
	}
	fclose(f);
}

/* exec program */
/* important: need to have #!/bin/bash in .sh script to execute it without error*/
void pulse_exec(char *name)
{
	int rv;
	struct stat sb;

	/* if file doesnt exist - just continue to work */
	if (stat(name, &sb) == -1) 
	{
		return;
	}

	/* clear and reset terminal in non-visual mode */
	endwin();
	clear();	

	/* ignore signals (SIGALARM) because they can finish our script */
	signal(SIGALRM, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);

	/* execl() returns only if error occured. return value is always -1 */
	rv = execl(name, name, (char*) NULL);

	/* have this error without #! /bin/bash */
	if (rv == -1)
	{
		printf(APP_ERROR "cannot execute : %s , rv : %d\n",name, rv);
		exit(EXIT_FAILURE);
	}
}

//-------------------------------------- network functions ---------------------
void pulse_get_gateway(char *intf)
{
	/* popen - open pipe. "r" - reading, "w" - writing */
	FILE *fp = popen("netstat -rn", "r");
	char line[256] = {0};

	/* reads 1 line in every iteration */
	while(fgets(line, sizeof(line), fp))
	{
		char *destination = strndup(line, 15);
		char* iface = strndup(line + 73, strlen(intf));
		
		if(!strcmp("0.0.0.0        ", destination) && 
		   !strcmp(iface, intf)) 
		{
			strncpy(pulse_net_str.gateway, line + 16, 15);
		}
		free(destination);
		free(iface);
	}
	pclose(fp);
}

/* parse /etc/resolv.conf. search for `nameserver`.
   take only 2 lines with keyword `nameserver` */
void pulse_get_dns()
{
	FILE *f = fopen("/etc/resolv.conf", "r");
	char line[256] = {0};
	char *keyword = "nameserver";
	char *key_ptr; /* pointer to found keyword */
	int cnt = 0;
	int i;

	if (!f) 
	{
		//printf("[error] can't open /etc/resolv.conf\n");
		return;
	}
	
	while(fgets(line, sizeof(line), f))
	{
		/* find keyword in line */
		key_ptr = strstr(line, keyword);
		if (key_ptr)
		{
			key_ptr += strlen(keyword)+1;
			strncpy(pulse_net_str.dns[cnt], key_ptr, ADDR_SIZE-1);
			/* stupid 0xa read from end of /etc/resolv.conf.
			   need to remove before use it mvprintw */
			for (i = 0; i < ADDR_SIZE; i++)
				if (pulse_net_str.dns[cnt][i] == 0xa)
					pulse_net_str.dns[cnt][i] = 0x0;
			cnt++;
			if (cnt == DNS_NUM) break;
		}
	}

	fclose(f);
}

void pulse_get_dhcpinfo()
{
	FILE *f = fopen("/etc/sysconfig/network-scripts/ifcfg-eth0", "r");
	char line[256] = {0};
	char *keyword = "dhcp";
	pulse_net_str.dhcp_enabled = 0;

	if (f)
	{	
		while(fgets(line, sizeof(line), f))
		{
			/* find keyword in line */
			if (strstr(line, keyword))
			{
				pulse_net_str.dhcp_enabled = 1;
				break;
			}
		}
		fclose(f);
	}
}

  /* int getifaddrs(struct ifaddrs **ifap) */
void pulse_get_netinfo()
{
	int i;
	int rv;
	int family; /* interface family */
	struct ifaddrs *ifaddr, *ifa;
	char host[NI_MAXHOST];
	/* static int intf_cnt = 0; */ /* count of interfaces */
	unsigned char *mac_ptr = pulse_net_str.mac;

	/* get all info about presented network interfaces
	   CARE. it will display same intf for 3 different families */
	if (getifaddrs(&ifaddr) == -1) 
	{
		//printf("getifaddrs() FAIL");
		return;
	}

	/* Walk through linked list */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
	{
		/* intf_cnt++; */

		/* this is important check to prevent crash in openvpn case */
		if (!ifa->ifa_addr)
			break;

		family = ifa->ifa_addr->sa_family;

		/* printf("#%d. intf: %s , family %d \n", intf_cnt, ifa->ifa_name,
				ifa->ifa_addr->sa_family); */

		/* we need ipv4 address and default interface only */
		if (family == AF_INET && !strcmp(ifa->ifa_name, DEF_INTF_NAME) )
		{
			/* save interface name */
			strcpy(pulse_net_str.name, ifa->ifa_name);
			/* address to name translation */
			rv = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),
				host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (!rv)
				strcpy(pulse_net_str.ip, host);
			rv = getnameinfo(ifa->ifa_netmask,sizeof(struct sockaddr_in),
				host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (!rv)
				strcpy(pulse_net_str.mask, host);
		}
		/* get MAC addr */
		if (family == AF_PACKET && !strcmp(ifa->ifa_name, DEF_INTF_NAME) )
		{
			struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
			for (i = 0; i < 6; i++)
			{
				//printf("0x%x ", s->sll_addr[i]);
				pulse_net_str.mac[i] = s->sll_addr[i];
			}
		}
		/* get gateway for DEFAULT interface */
		pulse_get_gateway(pulse_net_str.name);
	}

	freeifaddrs(ifaddr);

	/* get DNS */
	pulse_get_dns();

	/* get DHCP info */
	pulse_get_dhcpinfo();

}

void pulse_dump_netinfo()
{
	int i, j;
	
	unsigned char *mac_p = pulse_net_str.mac;

#if 0
	printf("name: %s \n", pulse_net_str.name);
	printf("ip: %s \n", pulse_net_str.ip);
	printf("mask: %s \n", pulse_net_str.mask);
	printf("mac:" "%02x:%02x:%02x:%02x:%02x:%02x\n",
		mac_p[0],mac_p[1],mac_p[2], mac_p[3],mac_p[4],mac_p[5]);
	printf("gateway: %s \n", pulse_net_str.gateway);
	for (i = 0; i < DNS_NUM; i++)
	{
		printf("dns %d : %s \n", i, pulse_net_str.dns[i]);
/*
		for (j = 0; j < ADDR_SIZE; j++)
			printf("0x%x ",pulse_net_str.dns[i][j]);
*/
	}
#endif
}


//-------------------------------------- system functions ---------------------

void pulse_get_hostname()
{
	gethostname(pulse_sys.hostname, HOSTNAME_SIZE);
	//printf("hostname: %s \n", pulse_sys.hostname);
}

/*
cat /proc/loadavg 
0.09 0.17 0.11 1/449 3832
*/
void pulse_get_cpuload()
{
	FILE *f = fopen("/proc/loadavg", "r");
	char line[256] = {0};

	if (!f) 
	{
		//printf("[error] can't open /proc\n");
		return;
	}

	while(fgets(line, sizeof(line), f))
	{
		strncpy(pulse_sys.cpuload, line, 14);
	}

	fclose(f);
}

/* us, ni, sy, id */
void pulse_get_cpuusage()
{
	FILE *f = fopen("/proc/stat", "r");
	char line[256] = {0};
	char *ptr;
	int cnt = 0;
	int charcnt = 0;
	char cputime[4][15] = {0}; /* us, ni, sy, id */
	int  intcputime[4];
	int i;
	int sum = 0;

	if (!f) 
	{
		//printf("[error] can't open /proc\n");
		return;
	}

	fgets(line, sizeof(line), f);
	ptr = line + 4;

	//printf("line %s \n", line);

	/* parse line and fill 4 strings with cputime */
	u8 digitstarted = 0;
	while (*ptr)
	{
		//printf("ptr %c \n", *ptr);
		if (*ptr >= '0' && *ptr <= '9')
		{
			cputime[cnt][charcnt++] = *ptr;
			digitstarted = 1;
		}
		else if (*ptr == ' ' && digitstarted)
		{
			cnt++;
			digitstarted = 0;
			charcnt = 0;
		}
		ptr++;
		if (cnt == 4) break;
	}

	/* convert strings to int */
	for (i = 0; i < 4; i++)
	{
		//printf("cputime string: %s \n", cputime[i]);
		intcputime[i] = atoi(cputime[i]);
		sum += intcputime[i];
		//printf("cputime %d \n",intcputime[i]);
	}

	int percent = sum / 100;
	if (!percent) percent = 1;
	
	pulse_sys.cpu_user = (intcputime[0] + intcputime[1]) / percent;
	pulse_sys.cpu_system = intcputime[2] / percent;
	pulse_sys.cpu_total = pulse_sys.cpu_user + pulse_sys.cpu_system;
	pulse_sys.cpu_idle = intcputime[3] / percent;

	fclose(f);
}

/* parse /proc/meminfo */
/*
MemTotal:        4049136 kB
MemFree:         2024324 kB
SwapTotal:             0 kB
SwapFree:              0 kB
*/
void pulse_get_meminfo()
{
	FILE *f = fopen("/proc/meminfo", "r");
	char line[256] = {0};
	char *keyword[4] = {"MemTotal","MemFree","SwapTotal","SwapFree"};
	char meminfo[4][12] = {0};
	char *ptr; /* pointer to found keyword */
	int charcnt = 0;
	int cnt = 0;
	int i;

	if (!f) 
	{
		//printf("[error] can't open /proc\n");
		return;
	}

	while(fgets(line, sizeof(line), f))
	{
		ptr = strstr(line, keyword[cnt]);
		if (ptr)
		{
			u8 digitstarted = 0;
			while (*ptr)
			{
				if (*ptr >= '0' && *ptr <= '9')
				{
					meminfo[cnt][charcnt++] = *ptr;
					digitstarted = 1;
				}
				else if (*ptr == ' ' && digitstarted)
				{
					cnt++;
					digitstarted = 0;
					charcnt = 0;
				}
				ptr++;
			}
			if (cnt == 4) break;
		}
	}

	/* convert strings to int. in KB */
	pulse_sys.mem_total = atoi(meminfo[0]);
	pulse_sys.mem_free = atoi(meminfo[1]);
	pulse_sys.swap_total = atoi(meminfo[2]); 
	pulse_sys.swap_free = atoi(meminfo[3]);

	fclose(f);
}

/* returns 0 - if we have found /var/data in /proc
   returns 1 - if not */
int pulse_parse_mounts()
{
	int rv = 1;
	FILE *f = fopen("/proc/mounts", "r");
	char line[256] = {0};
	char *keyword = "/var/data";

	if (f)
	{	
		while(fgets(line, sizeof(line), f))
		{
			if (strstr(line, keyword))
			{
				rv = 0;
				break;
			}
		}
		fclose(f);
	}

	return rv;
}

/* man statfs, statvfs */
void pulse_get_diskinfo()
{
	int r;
	struct statfs diskinfo;

	/* get root size and usage */
	if (!statfs("/",&diskinfo))
	{
		//pls_sizeof();

/*
		printf("block size %ld, total blocks %ld," 
			"free_blocks %ld, avail_blocks %ld \n",
		 diskinfo.f_bsize, diskinfo.f_blocks, 
		diskinfo.f_bfree, diskinfo.f_bavail); 
*/

		pulse_sys.disk_root_total = diskinfo.f_bsize*(diskinfo.f_blocks/KB);
		pulse_sys.disk_root_free = diskinfo.f_bsize*(diskinfo.f_bfree/KB);
		pulse_sys.disk_root_avail = diskinfo.f_bsize*(diskinfo.f_bavail/KB);
/*
		printf("root total %f, root free %f ,root avail %f\n",
		pulse_sys.disk_root_total,pulse_sys.disk_root_free,
		pulse_sys.disk_root_avail);
*/
	}
/*
	else
		printf("[error]. can't get diskinfo.\n");	
*/

	/* get /var/data size and usage */
	if (!statfs("/var/data",&diskinfo) && !pulse_parse_mounts() )

/*
		printf("block size %ld, total blocks %ld," 
			"free_blocks %ld, avail_blocks %ld \n",
		 diskinfo.f_bsize, diskinfo.f_blocks, 
		diskinfo.f_bfree, diskinfo.f_bavail); 
*/

		pulse_sys.disk_data_total = diskinfo.f_bsize*(diskinfo.f_blocks/KB);
		pulse_sys.disk_data_free = diskinfo.f_bsize*(diskinfo.f_bfree/KB);
		pulse_sys.disk_data_avail = diskinfo.f_bsize*(diskinfo.f_bavail/KB);
/*
		printf("data total %f, data free %f ,data avail %f\n",
		pulse_sys.disk_data_total,pulse_sys.disk_data_free,
		pulse_sys.disk_data_avail);
*/
	
}


/* get all system info */
void pulse_get_sysinfo()
{
	pulse_get_hostname();
	pulse_get_cpuload();
	pulse_get_cpuusage();
	pulse_get_meminfo();
	pulse_get_diskinfo();
}

/* main function to get network and system info. called just once during init */
void pulse_get_info()
{
	pulse_get_netinfo();
	pulse_get_sysinfo();
}

//---------------------------------draw functions ---------------------

void print_in_middle(WINDOW *win, int starty, int startx, int width, char *string)
{       
	int length, x, y;
        float temp;

        if(win == NULL)
                win = stdscr;
        getyx(win, y, x);
        if(startx != 0)
                x = startx;
        if(starty != 0)
                y = starty;
        if(width == 0)
                width = 80;

        length = strlen(string);
        temp = (width - length)/ 2;
        x = startx + (int)temp;
        mvwprintw(win, y, x, "%s", string);
        //refresh();
}

/* middle of screen */
void pulse_text_middle(int y, char* str)
{
	int length;
	int width;
	int startpos;

	length = strlen(str);
	width = term_cols;
	startpos = (width - length)/2;
	mvprintw(y, startpos, "%s", str);
}

void pulse_text_middleleft(int y, char* str)
{
	int length;
	int width;
	int startpos;

	length = strlen(str);
	width = term_cols/2;
	startpos = (width - length)/2;
	mvprintw(y, startpos, "%s", str);
}

/* middle of right area */
void pulse_draw_info_middle(int y, char* str)
{
	int length;
	int width;
	int startpos;

	length = strlen(str);
	width = term_cols/2;
	startpos = (width - length)/2 + term_cols/2;
	mvprintw(y, startpos, "%s", str);
}



void pulse_draw_borders()
{
	int y = INFO_ROW_START + 9;
	
        attron(COLOR_PAIR(2));
	mvhline(y, 1, 0, term_cols-2);
        attroff(COLOR_PAIR(2));
}


void pulse_draw_window()
{
	/* window border */
        attron(COLOR_PAIR(2));
	border('|', '|', 0, 0, '+', '+', '+', '+');
        attroff(COLOR_PAIR(2));
}

/* ----------used--------------> */
void pulse_draw_bar(int y, int x, int percents)
{
	int i;
	int num = percents/3;

	/* clear the whole bar with black */
	for (i = 0; i < BAR_SIZE; i++)
		mvprintw(y,x+i," ");

	mvprintw(y,x,"|");
	for (i = 1; i <= num; i++)
		mvaddch(y, x+i, ACS_BLOCK);
	mvprintw(y, x+BAR_SIZE+1, "|");
}

void pulse_draw_bg()
{
	int x,y;

	/* fill top line with black */
        attron(COLOR_PAIR(7));
	for (x = 0; x < term_cols; x++)
		mvprintw(0, x, " ");
        attroff(COLOR_PAIR(7));


	/* fill left side with yellow */
        attron(COLOR_PAIR(3));

	for (y = 1; y < BG_END; y++) 
		for (x = 0; x < term_cols/2; x++)
			mvprintw(y, x, " ");

        attroff(COLOR_PAIR(3));

	/* change CYAN color */
	if (can_change_color())
		init_color(COLOR_CYAN, 900, 900, 900);
	

	/* fill right side with white */
        attron(COLOR_PAIR(4));

	for (y = 1; y < BG_END; y++) 
		for (x = term_cols/2; x < term_cols; x++)
			mvprintw(y, x, " ");

        attroff(COLOR_PAIR(4));

	/* fill bottom with black */
        attron(COLOR_PAIR(7));
		for (y = BG_END; y < term_rows-1; y++)
			for (x = 0; x < term_cols; x++)
				mvprintw(y, x, " ");
        attroff(COLOR_PAIR(7));

	/* fill last line with white */
        attron(COLOR_PAIR(8));
	for (x = 0; x < term_cols; x++)
		mvprintw(term_rows-1, x, " ");
        attroff(COLOR_PAIR(8));


}

# if 0
void pulse_draw_hostname()
{

}
#endif

void pulse_draw_appname()
{
        attron(COLOR_PAIR(2));
	pulse_text_middle(0,"[ NSI Virtual Appliance ]");
        attroff(COLOR_PAIR(2));
}


void pulse_draw_config()
{
	int i;
	int y = INFO_ROW_START;

        attron(COLOR_PAIR(1));
	attron(A_UNDERLINE);
	pulse_text_middleleft(INFO_ROW_START -2,"System Info");
	attroff(A_UNDERLINE);

	for (i = 0; i < CONFIG_LINES_NUM; i++)
	{
		mvprintw(y++, MENU_COL_START,"%s", config_lines[i]);
	}

        attroff(COLOR_PAIR(1));
}

void pulse_draw_netinfo()
{
	int i;

	unsigned char *mac_p = pulse_net_str.mac;
	int y = INFO_ROW_START;

        attron(COLOR_PAIR(4));

	attron(A_UNDERLINE);
	pulse_draw_info_middle(INFO_ROW_START -2,"Network Info");
	attroff(A_UNDERLINE);

	mvprintw(y, term_cols/2 + MENU_COL_START, "Interface:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
		 pulse_net_str.name);

	mvprintw(y, term_cols/2 + MENU_COL_START, "DHCP:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
		 pulse_net_str.dhcp_enabled?"Enabled":"Disabled");

	mvprintw(y, term_cols/2 + MENU_COL_START, "IP Address:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
		 pulse_net_str.ip);

	mvprintw(y, term_cols/2 + MENU_COL_START, "Netmask:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
		 pulse_net_str.mask);

	mvprintw(y, term_cols/2 + MENU_COL_START, "Default Gateway:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
		 pulse_net_str.gateway);

	mvprintw(y, term_cols/2 + MENU_COL_START, "Mac Address:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET, 
		"%02x:%02x:%02x:%02x:%02x:%02x",
		mac_p[0],mac_p[1],mac_p[2], mac_p[3],mac_p[4],mac_p[5]);

	for (i = 0; i < DNS_NUM; i++)
	{
		mvprintw(y, term_cols/2 + MENU_COL_START, "DNS %d:", i+1);
		mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
			 pulse_net_str.dns[i]);
	}

        attroff(COLOR_PAIR(4));
}

void pulse_draw_sysinfo()
{
	int y = INFO_ROW_START + 10;
	int percent;

	pulse_text_middle(y++,pulse_sys.hostname);
	attron(A_UNDERLINE);
	pulse_text_middle(y,"System Status");
	attroff(A_UNDERLINE);
	y+=1;


	mvprintw(y, MENU_COL_START, "CPU");
	pulse_draw_bar(y, BAR_OFFSET, pulse_sys.cpu_total);
	mvprintw(y++, LOAD_FREE_OFFSET, "Load:   %s", pulse_sys.cpuload);

	mvprintw(y, MENU_COL_START, "Memory");
	percent = pulse_sys.mem_total/100;
	if (!percent) 
		pulse_draw_bar(y, BAR_OFFSET,0);
	else
		pulse_draw_bar(y,BAR_OFFSET,100-pulse_sys.mem_free/percent);
	mvprintw(y++, LOAD_FREE_OFFSET, "Free:   %dM / %dM", 
	pulse_sys.mem_free/1024, pulse_sys.mem_total/1024);

	mvprintw(y, MENU_COL_START, "Swap");
	percent = pulse_sys.swap_total/100;
	if (!percent) 
		pulse_draw_bar(y, BAR_OFFSET,0);
	else
		pulse_draw_bar(y,BAR_OFFSET,100-pulse_sys.swap_free/percent);
	mvprintw(y++, LOAD_FREE_OFFSET, "Free:   %dM / %dM", 
	pulse_sys.swap_free/1024, pulse_sys.swap_total/1024);

	/* disk info */
	mvprintw(y, MENU_COL_START, 
			pulse_sys.disk_data_total?"Disk (root)":"Disk");
	percent = pulse_sys.disk_root_total/100;
	if (!percent) 
		pulse_draw_bar(y, BAR_OFFSET,0);
	else
		pulse_draw_bar(y,BAR_OFFSET,100-pulse_sys.disk_root_avail/percent);
	mvprintw(y++, LOAD_FREE_OFFSET, "Free:   %.1fG / %.1fG", 
	pulse_sys.disk_root_avail/MB, pulse_sys.disk_root_total/MB);

	/* if /var/data mounted - show one more line */
	if (pulse_sys.disk_data_total) /* check for mounted /var */
	{
		mvprintw(y, MENU_COL_START, "Disk (data)");
		percent = pulse_sys.disk_data_total/100;
		if (!percent) 
			pulse_draw_bar(y, BAR_OFFSET,0);
		else
			pulse_draw_bar(y,BAR_OFFSET,
				100-pulse_sys.disk_data_avail/percent);
		mvprintw(y++, LOAD_FREE_OFFSET, "Free:   %.1fG / %.1fG", 
		pulse_sys.disk_data_avail/MB, pulse_sys.disk_data_total/MB);
	}

#if 0


	mvprintw(y, term_cols/2 + MENU_COL_START, "Hostname:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
			 pulse_sys.hostname);

	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
			 pulse_sys.cpuload);

	mvprintw(y, term_cols/2 + MENU_COL_START, "CPU Usage:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
		"User %d%% Sys %d%% Idle %d%%", pulse_sys.cpu_user,
		pulse_sys.cpu_system, pulse_sys.cpu_idle);
	mvprintw(y, term_cols/2 + MENU_COL_START, "Memory Total:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
		"%dM   Free: %dM", 
		pulse_sys.mem_total, pulse_sys.mem_free);
	mvprintw(y, term_cols/2 + MENU_COL_START, "Swap Total:");
	mvprintw(y++, term_cols/2 + MENU_COL_START + INFO_OFFSET,
		"%dM   Free: %dM", 
		pulse_sys.swap_total, pulse_sys.swap_free);

	mvprintw(y++, term_cols/2 + MENU_COL_START, "Disk Free Root:");

	mvprintw(y++, term_cols/2 + MENU_COL_START, "Disk Free Data:");
#endif
}

#if 0
void pulse_draw_version()
{
	mvprintw(term_rows-2, 1, "BOOTConfig version %.2f \n", VERSION);
}
#endif


/* main func to draw whole info at once! */
void pulse_draw_info()
{
	pulse_draw_config();
	pulse_draw_netinfo();
	pulse_draw_sysinfo();
}

void pulse_draw_fbuttons()
{
        attron(COLOR_PAIR(4));
	if (bnglobal.nologin)
		mvprintw(term_rows-1, 1, "[F2 Setup] [F3 Support]");
	else
		mvprintw(term_rows-1, 1, "[F1 Login] [F2 Setup] [F3 Support]");
	mvprintw(term_rows-1, term_cols-13, "[F12 Reboot]");
        attroff(COLOR_PAIR(4));
}

void pulse_clear_menu()
{
	int x,y;

        attron(COLOR_PAIR(3));

	for (y = MENU_ROW_START; y < MENU_ROW_END; y++) 
		for (x = MENU_COL_START; x < term_cols/2; x++)
			mvprintw(y, x, " ");

        attroff(COLOR_PAIR(3));
}

void pulse_clear_info()
{
	int x,y;

	/* fill right side with white */
        attron(COLOR_PAIR(4));

	/* clear only part of the screen selected by INFO_ROW_START/END */
	for (y = INFO_ROW_START; y < INFO_ROW_END; y++) 
		for (x = term_cols/2; x < term_cols-1; x++)
			mvprintw(y, x, " ");

        attroff(COLOR_PAIR(4));
}

void pulse_draw_focus()
{
	int x;

	// 1. draw black focus line.
        attron(COLOR_PAIR(2));
	for (x = MENU_COL_START; x < FOCUS_SIZE; x++)
		mvprintw(pulse_cur.row, x, " ");
        attroff(COLOR_PAIR(2));

	// 2. draw menu name with other color.
        attron(COLOR_PAIR(5));
		mvprintw(MENU_ROW_START+menu_cnt, MENU_COL_START, menu[menu_cnt]);
        attroff(COLOR_PAIR(5));
}


void pulse_draw_win_shut_focus()
{
	int x;

	// 1. draw focus line.
	init_pair(3, COLOR_YELLOW, COLOR_YELLOW);
        attron(COLOR_PAIR(3));
	for (x = WIN_SHUT_MENU_COL_START; x < WIN_SHUT_FOCUS_SIZE; x++)
	{
		//debug(28+x,1, "%d", WIN_SHUT_ROW_START+win_shut_menu_cnt);
		mvwprintw(bnglobal.win_shut, WIN_SHUT_MENU_ROW_START + 
			win_shut_menu_cnt ,x," ");
	}
        attroff(COLOR_PAIR(3));

	// 2. draw menu name with other color.
	init_pair(6, COLOR_WHITE, COLOR_RED); 
        attron(COLOR_PAIR(6));
		mvwprintw(bnglobal.win_shut, WIN_SHUT_MENU_ROW_START + win_shut_menu_cnt,
			WIN_SHUT_MENU_COL_START, win_shut_menu[win_shut_menu_cnt]);
        attroff(COLOR_PAIR(6));
}


/* draws menu header and menu */
void pulse_draw_menu()
{
	int i;

        attron(COLOR_PAIR(1));

	/* draw menu header */
#if 0
	attron(A_UNDERLINE);
	mvprintw(1, MENU_COL_START, "SYSTEM MENU");
	attroff(A_UNDERLINE);
#endif

	/* draw menu items */
	for (i = 0; i < MENU_ITEMS_NUM; i++)
	{
		mvprintw(MENU_ROW_START+i, MENU_COL_START, menu[i]);
	}
	
        attroff(COLOR_PAIR(1));
}

/* draws selected menu item in header of info area */
void pulse_draw_info_header()
{
	int x;

        attron(COLOR_PAIR(4));

	for (x = term_cols/2; x < term_cols-1; x++)
		mvprintw(1, x, " ");

        attroff(COLOR_PAIR(4));
	mvprintw(1, MENU_COL_START+term_cols/2, menu[menu_cnt]);
}

/* main draw func */
void pulse_draw()
{
	pulse_draw_bg();
	pulse_draw_appname();
	//pulse_draw_menu();
	pulse_draw_info();
	//pulse_draw_info_header();
	//pulse_draw_focus();
	//pulse_draw_window();

        attron(COLOR_PAIR(4));
	//pulse_draw_borders();
	pulse_draw_fbuttons();
        attroff(COLOR_PAIR(4));

        refresh();
}

void pulse_draw_win_shut()
{	
	int x = WIN_SHUT_MENU_COL_START;
	int y = WIN_SHUT_MENU_ROW_START;
	int i;

        wattron(bnglobal.win_shut, COLOR_PAIR(2));

	box(bnglobal.win_shut, 0, 0);
	for (i = 0; i < WIN_SHUT_MENU_ITEMS_NUM; i++)
		mvwprintw(bnglobal.win_shut,y++,x,win_shut_menu[i]);

        wattroff(bnglobal.win_shut, COLOR_PAIR(2));

	pulse_draw_win_shut_focus();

	debug(27, 1, "win_shut_menu_cnt %d ", win_shut_menu_cnt);
	wrefresh(bnglobal.win_shut);
	refresh();
}

void pulse_draw_win_info()
{	
	int x = WIN_INFO_MENU_COL_START;
	int y = WIN_INFO_MENU_ROW_START;
	int i;

        wattron(bnglobal.win_info, COLOR_PAIR(2));

	box(bnglobal.win_info, 0, 0);
	for (i = 0; i < win_info.lines; i++)
		mvwprintw(bnglobal.win_info,y++,x,info_lines[i]);

        wattroff(bnglobal.win_info, COLOR_PAIR(2));

	wrefresh(bnglobal.win_info);
	refresh();
}


void pulse_ncurses_init()
{
	initscr();     
        start_color();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	/* get num of rows and cols in terminal */
	getmaxyx(stdscr,term_rows,term_cols);
	//printw("colors: %d \n", COLOR_PAIRS);

	/* init pairs */
	init_pair(1, COLOR_BLACK, COLOR_YELLOW);
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);
	init_pair(3, COLOR_YELLOW, COLOR_YELLOW);
	init_pair(4, COLOR_BLACK, COLOR_WHITE); 
	init_pair(5, COLOR_WHITE, COLOR_BLACK); 
	init_pair(6, COLOR_WHITE, COLOR_RED); 
	init_pair(7, COLOR_BLACK, COLOR_BLACK); 
	init_pair(8, COLOR_WHITE, COLOR_WHITE); 
	init_pair(9, COLOR_MAGENTA, COLOR_MAGENTA); /* debug purpose */
}


void pulse_create_shutdown_win()
{
	int x, y;
	x = (term_cols - WIN_SHUT_W) / 2;
	y = (term_rows - WIN_SHUT_H) / 2;

	/* lines, cols, y, x */
	bnglobal.win_shut = newwin(WIN_SHUT_H, WIN_SHUT_W, y, x);

	debug(25, 1, "term: cols %d, rows %d ", term_cols, term_rows);
	debug(26, 1, "win shut: h:%d w:%d y:%d x:%d ",
		WIN_SHUT_H, WIN_SHUT_W, 
		bnglobal.win_shut->_begy, bnglobal.win_shut->_begx);
	
	pulse_draw_win_shut();
	bnglobal.window = WIN_SHUT;
}

void pulse_create_win_info()
{
	int x, y;

	x = (term_cols - win_info.chars) / 2;
	y = (term_rows - win_info.lines) / 2;

	/* lines, cols, y, x */
	bnglobal.win_info = newwin(win_info.h, win_info.w, y, x);
	
	if (bnglobal.win_info)
		debug(29, 1, "win_info created");

	debug(30, 1, "win info: h:%d w:%d y:%d x:%d ",
		win_info.lines, win_info.chars, 
		bnglobal.win_info->_begy, bnglobal.win_info->_begx);
	
	pulse_draw_win_info();
	bnglobal.window = WIN_INFO;
}


void pulse_destroy_shutdown_win()
{
	delwin(bnglobal.win_shut);
	bnglobal.window = WIN_MAIN;
	pulse_draw();
}

void pulse_destroy_win_info()
{	
	delwin(bnglobal.win_info);
	bnglobal.window = WIN_MAIN;
	pulse_draw();
}

void pulse_keyboard()
{
	int ch;
	
        ch = getch();
	switch(ch)
	{      
		case 27: /* ESCAPE KEY */
			if (bnglobal.window == WIN_MAIN)
				pulse_exit();
			else if (bnglobal.window == WIN_SHUT)
				pulse_destroy_shutdown_win();	
			else if (bnglobal.window == WIN_INFO)
				pulse_destroy_win_info();
			break;

		case KEY_F(1):
			if (bnglobal.window == WIN_MAIN)
				if (!bnglobal.nologin)
					pulse_exec(F1_EXE);
			break;	
		case KEY_F(2):
			if (bnglobal.window == WIN_MAIN)
				pulse_exec(F2_EXE);
			break;
		case KEY_F(3):
			if (bnglobal.window == WIN_MAIN)
				pulse_exec(F3_EXE);
			break;
		case KEY_F(12):
			if (bnglobal.window == WIN_MAIN)
				pulse_create_shutdown_win();
			break;
		case KEY_DOWN:
			if (bnglobal.window == WIN_MAIN)
			{
			/*
				if (++menu_cnt == MENU_ITEMS_NUM)
					menu_cnt = 0;
			*/
			}
			else if (bnglobal.window == WIN_SHUT)
			{
				if (++win_shut_menu_cnt == WIN_SHUT_MENU_ITEMS_NUM)
					win_shut_menu_cnt = 0;
				pulse_draw_win_shut(); /* redraw window */
			}
			break;
		case KEY_UP:
			if (bnglobal.window == WIN_MAIN)
			{
			/*
				if (-- menu_cnt < 0)
					menu_cnt = MENU_ITEMS_NUM-1;
			*/
			}
			else if (bnglobal.window == WIN_SHUT)
			{
				if (-- win_shut_menu_cnt < 0)
					win_shut_menu_cnt = WIN_SHUT_MENU_ITEMS_NUM-1;
				pulse_draw_win_shut(); /* redraw window */
			}
			break;
		case 10: /* ENTER */
			if (bnglobal.window == WIN_SHUT)
			{
				if (win_shut_menu_cnt == 0)
				{
					pulse_exec(SHUTDOWN_EXE);
				}	
				else if (win_shut_menu_cnt == 1)
				{
					pulse_exec(REBOOT_EXE);
				}
				else if (win_shut_menu_cnt == 2)
				{
					pulse_destroy_shutdown_win();
					win_shut_menu_cnt = 0;
				}
			}
			else if (bnglobal.window == WIN_INFO)
			{
				pulse_destroy_win_info();
			}
			break;
		default:
			break;
	}
		//printf("keycode %d \n", ch);
}

void pulse_engine()
{
	pulse_cur.row = menu_cnt + MENU_ROW_START;
	move(pulse_cur.row, pulse_cur.col);
}



/* signal handlers -----------------------------------------------------------*/

/* update sysinfo, program new alarm */
void sigalarm_handler(int signum)
{
	if (bnglobal.window == WIN_MAIN)
	{
		pulse_get_sysinfo();
		pulse_draw_sysinfo();
		refresh();
	}
	alarm(TIME_TO_REFRESH);
}

/* reread config */
void sigusr1_handler(int signum)
{
	pulse_read_config();
	pulse_check_nologin();
	pulse_draw();
}

int main(int argc, char *argv[])
{
	printf(APP_NAME "version %s \n", VERSION);

	/* init --------------------------------------------------- */
	pulse_init();
	pulse_check_nologin();
	pulse_check_boot_info();
	pulse_read_config();
	pulse_get_info();
	//pulse_dump_netinfo();
	pulse_ncurses_init();

	/* settings ----------------------------------------------- */
	move(pulse_cur.row, pulse_cur.col);
	curs_set(0);
	//nodelay(stdscr,true); /* disabling waiting on getch */

	/* setup signals */
	signal(SIGALRM, sigalarm_handler);
	signal(SIGUSR1, sigusr1_handler);
	alarm(TIME_TO_REFRESH);

	pulse_draw();
	
	if (bnglobal.boot_info)
		pulse_create_win_info();

	while (1)
	{
		pulse_keyboard();
		//pulse_engine();
		//usleep(1000);
	}

	return 0;
}
