/*
 * iProtect for Apache 1.3
 *
 * Copyright 1999-2003, Digital Concepts
 *
 * http://www.digital-concepts.net
 */

#define IPROT_VERSION "1.9.0-beta17"
#define SUPPORT_MAIL_URL "mailto:iprotect@digital-concepts.net"
#define COPYRIGHT_NOTICE "Copyright 1999-2003, Digital Concepts"

#include "httpd.h"
#include "http_main.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_script.h"

#include <db.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

module MODULE_VAR_EXPORT iprot_module;

#if APACHE_RELEASE < 1030900
ARGH!  Apache Release 1.3.9 or newer required!
#endif

/* bytes in a megabyte */
#define MBYTE 1024000
/* seconds in an hour */
#define SEC_PER_HOUR (60 * 60)

#ifndef TRUE
#  define TRUE 1
#endif

#ifndef FALSE
#  define FALSE 0
#endif

#undef THREAD_SAFE
/* use strerror_r() instead of strerror(),
 * ctime_r() instead of ctime(),
 * localtime_r() instead of localtime()
 */
#define DISPLAY_DB TRUE
#define DEBUG TRUE

#define IPROT_DB_EXT ".db"

#define IPROT_DB_RW_FLAGS 0
#define IPROT_DB_RO_FLAGS DB_RDONLY
#define IPROT_DB_PERMS S_IRUSR | S_IWUSR
#define DB_TXN_FLAGS 0
#define DB_TYPE DB_HASH

#define LOG_ERROR(CONF, FMT, VAR)\
 (ap_log_error(APLOG_MARK, APLOG_WARNING, CONF, FMT, VAR))
#define LOG_PRINTF(CONF, FMT, VAR)\
 (ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, CONF, FMT, VAR))
#define PALLOC ap_palloc
#define GET_MODULE_CONFIG ap_get_module_config
#define PSTRDUP ap_pstrdup

#define isusername(item) index (item, '.') == NULL
#define Print_Plural(val) (val > 1) ? "s" : ""

#define DATA_STR_SEP_C	'\xbb'	/* '»' */

#define S_CHAR		'?'
#define S_CHAR_MAILED	'\xbf'; /* '¿' */

#define UPDATED_KEY	   "-*-updated-*-"

#define ERR_STR_BUF_SIZE 128
#define TIME_STR_BUF_SIZE 32

/* some default values */
#define IPROT_THRESHOLD		10	/* num hits */
#define IPROT_AUTH_TIMEOUT	300	/* timeout for authorizations */
#define IPROT_ACCESS_TIMEOUT	24	/* hours */
#define IPROT_DB_FILE		"/tmp/iprot"
#define IPROT_BLOCKIGNORE_DB_FILE "iprot/iprot_block_ignore"
#define IPROT_COMPARE_N		2
#define IPROT_FAILED_THRESHOLD	3	/* threshold number of ips for
				 	 * failed login for one user */
#define IPROT_FAILED_TIMEOUT	300	/* timeout for failed logins */
#define IPROT_FAILED_COMPARE_N	3
#define IPROT_MAX_BYTES_USER	0	/* default is disabled */
#define IPROT_BW_STATUS_RETURN	1	/* return HTTP STATUS Forbidden (403) 
					 * status by default */
#define IPROT_BW_TIMEOUT	0
#define IPROT_BW_REDIRECT_URL	NULL	/* WARNING! if any NULL constants
					 * are changed create_prot_config() */
#define IPROT_EMAIL		NULL	/* and merge_prot_config() must also */
#define IPROT_ABUSE_EMAIL	NULL	/* be changed. Changing other */
#define IPROT_HACK_EMAIL	NULL	/* constants may also affect */
#define IPROT_BW_EMAIL		NULL	/* create_prot_config() and
					 * merge_prot_config() */
#define IPROT_EXTERNAL_PROGIP	NULL
#define IPROT_EXTERNAL_PROGUSER	NULL

#define IPROT_ABUSE_STATUS_RETURN 1  /* return HTTP STATUS Forbidden (403) */
#define IPROT_HACK_STATUS_RETURN  1  /* status by default */
#define IPROT_ABUSE_REDIRECT_URL  NULL
#define IPROT_HACK_REDIRECT_URL	  NULL

#define IPROT_NAG		0  /* sent email every time a user/ip
				    * is blocked */
#define IPROT_NOTIFY_IP		1  /* send hack attempt mail by default */
#define IPROT_NOTIFY_USER	1  /* send abuse mail by default */
#define IPROT_NOTIFY_LOGIN	1  /* send failed login mail by default */
#define IPROT_NOTIFY_BW		1  /* send bw block mail by default */

#define IPROT_ENABLED		1  /* enabled by default */
#define IPROT_NO_HEAD_REQ	0  /* allow HEAD requests by default */
#define IPROT_ALL_HOSTS_ADMIN	0  /* show all hosts in admin off by default */

#define IPROT_IPADDRESS_PREG	"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"
#define IPROT_IGNORE_IPS_TABLE_SIZE   20
#define IPROT_IGNORE_USERS_TABLE_SIZE 20


/* structure holding info from config files */
typedef struct {
  int threshold;
  int auth_timeout;
  int access_timeout;
  int compareN;
  char *email;
  char *abuse_email;
  char *hack_email;
  char *bw_email;
  int nag;
  char *external_progip;
  char *external_proguser;
  int failed_threshold;
  int failed_timeout;
  int failed_compareN;
  int abuse_status_return;
  char *abuse_redirect_url;
  int hack_status_return;
  char *hack_redirect_url;
  char *filename;
  char *block_ignore_filename;
  int enabled;		/* auth enabled flag */
  int notifyip;
  int notifyuser;
  int notifylogin;
  int notifybw;
  int no_HEAD_req;
  int all_hosts_admin;
  int bw_status_return;
  int max_bytes_user;
  char *bw_redirect_url;
  int bw_timeout;
  table *ignore_ips;
  table *ignore_users;
  regex_t *ipaddress_preg;
  DB_ENV *db_envp;
  DB *iprot_db;
  DB *block_ignore_db;
} prot_config_rec;

/* iprot_admin.c */
#define N_NEW_BLOCKS 4
	/* N_NEW_BLOCKS must be less that 100 */
#define TARGET_NAME_LENGTH "32"

int iprot_admin(request_rec *r);

/* iprot_db.c */
int new_str_from_datum(const DBT *d, char **str, request_rec *r);

DB_ENV *create_db_env(char *db_home,
		      int extra_flags,
		      int mode, server_rec *s);

DB *open_db(DB_ENV *db_envp,
	    const char *filename,
	    const int flags,
	    const int mode,
	    server_rec *s);

int close_db_env(DB_ENV **db_envp, server_rec *s);

int transaction_start(server_rec *s, 
		      DB_ENV *db_envp,
		      DB_TXN *parent_txn_id,
		      DB_TXN **txn_id,
		      u_int32_t flags);

void transaction_abort(server_rec *s, DB_TXN *txn_id);

void transaction_commit(server_rec *s, DB_TXN *txn_id, u_int32_t flags);

void close_db(DB **dbp, server_rec *s);

int get_record(DB_TXN *txn_id,
	       DB *db,
	       DBT *db_data,
	       const char *host,
	       const char *target,
	       request_rec *r);

int get_cursor(DB_TXN *txn_id,
	       DB *db,
	       DBC **cursorp,
	       request_rec *r);

int get_cursor_record(DB_TXN *txn_id,
		      DBC *cursor,
		      DBT *db_key,
		      DBT *db_data,
		      u_int32_t flags,
		      request_rec *r);

int store_record(DB_TXN *txn_id,
		 DB *db,
		 const char *host,
		 const char *target,
		 const char *value,
		 const request_rec *r);

int delete_record(DB_TXN *txn_id,
		  DB *db,
		  const char *host,
		  const char *target,
		  const request_rec *r);

DB *open_iprot_db(DB_ENV *db_envp,
		  const char *filename,
		  const int flags,
		  const int mode,
		  request_rec *r);

int get_data_strings(request_rec *r,
		     const DBT *d,
		     char **p_str_1,
		     char **p_str_2,
		     char **p_str_3,
		     char **p_str_4);

char *combine_data_strings(request_rec *r,
			   const char *str_1,
			   const char *str_2,
			   const char *str_3,
			   const char *str_4);

char block_ignore_expired(DB *db,
			  const char *host,
			  const char *target, 
			  const time_t timestamp,
			  const time_t request_time);

char isipaddress(const prot_config_rec *config_rec, const char *item);

enum del_types { BLOCK_IGNORE_DELETE = 1, BLOCK_DELETE = 2 };

int delete_block_ignore(request_rec *r,
			const char *server_hostname,
			const char *target,
			enum del_types action);

int check_block_ignore(const char *BlockIgnoreStr,
		       const char *server_hostname,
		       const char *target,
		       request_rec *r);

void get_items(char *item, char **item_1, char **item_2, request_rec *r);

#define ITEM_SIZE 128
typedef struct {
  char item[ITEM_SIZE];
  long timestamp;
} footprint;

int get_footprint_list(char *footprintStr, footprint *footprint_list,
		       time_t request_time, time_t *expires);

int diff_day(time_t block_time,
	     time_t current_time);

int periodic_block_expired(time_t block_time,
			   time_t timeout,
			   time_t current_time);

time_t block_expires(time_t block_time,
		     time_t timeout,
		     time_t current_time);

