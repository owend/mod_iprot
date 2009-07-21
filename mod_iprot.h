/*
 * iProtect for Apache 1.3
 *
 * Copyright 1999-2003, Digital Concepts
 *
 * http://www.digital-concepts.net
 */

#define IPROT_VERSION "1.9.0-beta12"
#define SUPPORT_MAIL_URL "mailto:iprotect@digital-concepts.net"
#define COPYRIGHT_NOTICE "Copyright 1999-2003, Digital Concepts"

#include "httpd.h"
#include "http_main.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_script.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ndbm.h>


#define MBYTE 1024000  /* bytes in a megabyte */

#ifndef TRUE
#  define TRUE 1
#endif

#ifndef FALSE
#  define FALSE 0
#endif

#define DISPLAY_DB FALSE

#if defined O_EXLOCK
#  define IPROT_DB_FLAGS O_RDWR | O_CREAT | O_EXLOCK
#else
#  define IPROT_DB_FLAGS O_RDWR | O_CREAT
#endif

#if APACHE_RELEASE < 1030900
ARGH!  Apache Release 1.3.9 or newer needed!
#endif

#define LOG_ERROR(CONF, FMT, VAR)\
 (ap_log_error(APLOG_MARK, APLOG_WARNING, CONF, FMT, VAR))
#define LOG_PRINTF(CONF, FMT, VAR)\
 (ap_log_error(APLOG_MARK, APLOG_INFO, CONF, FMT, VAR))
#define PALLOC ap_palloc
#define GET_MODULE_CONFIG ap_get_module_config
#define PSTRDUP ap_pstrdup

module MODULE_VAR_EXPORT iprot_module;

#define isusername(item) index (item, '.') == NULL

#define DATA_STR_SEP_C  '\xbb'	/* '»' */

#define S_CHAR		'?'
#define S_CHAR_MAILED	'\xbf'; /* '¿' */

#define UPDATED_KEY "-*-updated-*-"

/* some default values */
#define IPROT_THRESHOLD		"10"
#define IPROT_AUTH_TIMEOUT	"300"
#define IPROT_ACCESS_TIMEOUT	"24"
#define IPROT_DB_FILE		"/tmp/iprot"
#define IPROT_BLOCKIGNORE_DB_FILE "iprot/iprot_block_ignore"
#define IPROT_COMPARE_N		"2"
#define IPROT_FAILED_THRESHOLD	"3"
#define IPROT_FAILED_TIMEOUT	"300"
#define IPROT_FAILED_COMPARE_N	"3"
#define IPROT_MAX_BYTES_USER	"0"

/* structure holding info from config files */
typedef struct {
  char *threshold;
  char *auth_timeout;
  char *access_timeout;
  char *filename;
  char *compareN;
  char *email;
  char *abuse_email;
  char *hack_email;
  char *bw_email;
  int nag;
  char *external_progip;
  char *external_proguser;
  char *failed_threshold;
  char *failed_timeout;
  char *failed_compareN;
  int abuse_status_return;
  char *abuse_redirect_url;
  int hack_status_return;
  char *hack_redirect_url;
  char *block_ignore_filename;
  int enabled;		/* auth enabled flag */
  int notifyip;
  int notifyuser;
  int notifylogin;
  int notifybw;
  int no_HEAD_req;
  int all_hosts_admin;
  int bw_status_return;
  char *max_bytes_user;
  char *bw_redirect_url;
  table *ignore_ips;
  table *ignore_users;
  regex_t *ipaddress_preg;
} prot_config_rec;

/* iprot_admin.c */
#define N_NEW_BLOCKS 4
	/* N_NEW_BLOCKS must be less that 100 */
#define TARGET_NAME_LENGTH "24"

int iprot_admin(request_rec *r);

/* iprot_db.c */
int new_str_from_datum(const datum *d, char **str, request_rec *r);

DBM *open_db(const char *filename, const int flags,
	     const int mode, request_rec *r);

int get_record(DBM *db, datum *d,
	       const char *host, const char *key,
	       const request_rec *r);

int store_record(DBM *db, const char *host, const char *key,
		 const char *value, const request_rec *r);

int delete_record(DBM *db, const char *host,
		  const char *key, const request_rec *r);

DBM *open_iprot_db(const char *filename, const int flags,
		   const int mode, request_rec *r);

int get_data_strings(request_rec *r,
		     const datum *d,
		     char **p_str_1,
		     char **p_str_2,
		     char **p_str_3,
		     char **p_str_4);

char *combine_data_strings(request_rec *r,
			   const char *str_1,
			   const char *str_2,
			   const char *str_3,
			   const char *str_4);

char block_ignore_expired(DBM *db, const char *host, const char *key, 
			   const time_t timestamp, const time_t request_time);

char isipaddress(const prot_config_rec *config_rec, const char *item);

enum del_types { BLOCK_IGNORE_DELETE = 1, BLOCK_DELETE = 2 };

int delete_block_ignore(request_rec *r, DBM *block_ignore_db, DBM *iprot_db,
			const char *server_hostname, const char *target,
			enum del_types action);

int check_block_ignore(const char *BlockIgnoreStr, DBM *iprot_db,
		       const char *server_hostname, const char *target,
		       prot_config_rec *config_rec, request_rec *r);

void get_items(char *item, char **item_1, char **item_2);

#define ITEM_SIZE 128
typedef struct {
  char item[ITEM_SIZE];
  long timestamp;
} footprint;

int get_footprint_list(char *footprintStr, footprint *footprint_list,
		       time_t request_time, time_t *expires);

int diff_day(time_t time_1, time_t time_2);

