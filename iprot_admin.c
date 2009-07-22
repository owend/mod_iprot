/*
 * iProtect for Apache
 *
 * Copyright 1999-2003, Digital Concepts
 *
 * http://www.digital-concepts.net
 */

#include "mod_iprot.h"
#include "util_uri.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


#undef DEBUG

#define DEFAULT_ENCTYPE "application/x-www-form-urlencoded"

#define On_Off(val) (val) ? "On" : "Off"
#define Print_Plural(val) (val > 1) ? "s" : ""

#define TABLE_BORDER "2"

typedef struct {
  request_rec *r;
  enum del_types del_type;
  int result;
} callback_data;

typedef struct db_filename_list *db_filename_list_ptr;

typedef struct db_filename_list {
  char *db_filename;
  char *bi_db_filename;
  db_filename_list_ptr next;
} db_filename_list_rec;

#ifdef X
static char *weekdays[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
#endif

static int get_params(request_rec *r, const char **rbuf)
{
  int rc;

  if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
    return rc;
  }

  if (ap_should_client_block(r)) {
    char argsbuffer[HUGE_STRING_LEN];
    int rsize, len_read, rpos = 0;
    long length = r->remaining;

    if (!(*rbuf = PALLOC(r->pool, length + 1))) {
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
      return DECLINED;
    }

    ap_hard_timeout("get_params", r);

    while ((len_read =
	    ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
      ap_reset_timeout(r);
      if ((rpos + len_read) > length)
	rsize = length - rpos;
      else 
	rsize = len_read;
      memcpy((char *)*rbuf + rpos, argsbuffer, rsize);
      rpos += rsize;
    }

    memcpy((char *)*rbuf + rpos, "\0x0", 1); /* terminating NULL */
    ap_kill_timeout(r);
  }

  return rc;
} /*  get_params */

static int read_post_params(request_rec *r, table **post_params_table)
{
  const char *data = NULL;
  const char *key, *value, *type;
  int result;

  if (r->method_number != M_POST)
    return OK;

  type = ap_table_get(r->headers_in, "Content-Type");
  if (strcasecmp(type, DEFAULT_ENCTYPE) != 0)
    return DECLINED;

  if ((result = get_params(r, &data)) != OK)
    return result;

  if (*post_params_table)
    ap_clear_table(*post_params_table);
  else
    *post_params_table = ap_make_table(r->pool, 8);

  if (!*post_params_table) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return DECLINED;
  }

  while(*data && (value = ap_getword(r->pool, &data, '&'))) {
    if (!value) {
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
      return DECLINED;
    }

    key = ap_getword(r->pool, &value, '=');
    if (!key) {
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
      return DECLINED;
    }

    ap_unescape_url((char*) key);
    ap_unescape_url((char*) value);

    ap_table_merge(*post_params_table, key, value);
  }

  return OK;
} /* read_post_params */

#ifdef Y
static char *asc_interval(time_t interval)
{
  static char time_str[24];
  int days;

  days = interval / 86400;
  interval = interval % 86400;

  if (days)
    snprintf(time_str, 24, "%i day%s %.8s",
	   days, (days > 1) ? "s" : "",
	   asctime(gmtime(&interval)) + 11);
  else
    snprintf(time_str, 24, "%.8s\n",
	     asctime(gmtime(&interval)) + 11);

  return time_str;
} /* asc_interval */
#endif

static char *asc_time(const time_t time)
{
  return ctime(&time);

#ifdef X
  static char time_str[24];
  struct tm *ts;

  ts = localtime(&time);
  snprintf(time_str, 24, "%s %02i/%02i/%i %02i:%02i:%02i",
	   weekdays[ts->tm_wday],
	   ts->tm_mon + 1, ts->tm_mday, 1900 + ts->tm_year,
	   ts->tm_hour, ts->tm_min, ts->tm_sec);

  return time_str;
#endif
} /* asc_time */

static void print_footprintStr(request_rec *r,
			       char *footprintStr, /* changed */
			       const int leading_cell)
{
  int i = 0, num_ips = 0;
  char target[128];
  time_t timestamp, current_time;
  char *str_p;

  if (!strcmp(footprintStr, ""))
    return;	/* oops empty string, bailout avoid SIGSEGV */

  current_time = time(NULL);
  num_ips = (str_p = strtok(footprintStr, "?\xbf"/* ? and ¿ */)) ?
    atoi(str_p) : 0;
  
  for (i = 0; i < num_ips; i++) {
    strncpy(target, (str_p = strtok(NULL, ":")) ? str_p : "", 128);
    timestamp = (time_t) (str_p = strtok(NULL, ";")) ? atol(str_p) : 0;

    ap_rputs("<tr>\n", r);
    if (leading_cell)
      ap_rputs("<td></td>\n", r);
    ap_rprintf(r, "<td>%s</td>\n", target);

    if (timestamp > current_time)
      ap_rprintf(r, "<td>%s</td>\n",
		 asc_time(timestamp));
    /*asc_interval(timestamp - r->request_time));*/
    else
      ap_rputs("<td>expired</td>\n", r);

    ap_rputs("</tr>\n", r);
  }
} /* print_footprintStr */

static int add_db_filenames(const char *db_filename,
			    const char *bi_db_filename,
			    db_filename_list_ptr *fn_list,
			    request_rec *r)
{
  char *fn;
  char *bi_fn;
  db_filename_list_ptr list = *fn_list;
  db_filename_list_ptr list_rec;

  if (!db_filename || !bi_db_filename) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, r, "NULL filename passed"
		  " to add_db_filenames()");
    return FALSE;
  }

  fn = (char *) PSTRDUP (r->pool, db_filename);
  bi_fn = (char *) PSTRDUP (r->pool, bi_db_filename);

  list_rec =
    (db_filename_list_ptr) PALLOC (r->pool, sizeof(db_filename_list_rec));

  if (!fn || !bi_fn|| !list_rec) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return FALSE;
  }

  list_rec->db_filename = fn;
  list_rec->bi_db_filename = bi_fn;

  *fn_list = list_rec;
  list_rec->next = list;

  return TRUE;
} /* add_db_filenames */

static int check_db_filename(const char *db_filename,
			     db_filename_list_ptr fn_list)
{
  if (db_filename)
    while (fn_list) {
      if (fn_list->db_filename &&
	  !strcmp(db_filename, fn_list->db_filename))
	return TRUE;

      fn_list = fn_list->next;
    }

  return FALSE;
} /* check_db_filename */

static int check_bi_db_filename(const char *bi_db_filename,
				db_filename_list_ptr fn_list)
{
  while (fn_list) {
    if (fn_list->bi_db_filename &&
	!strcmp(bi_db_filename, fn_list->bi_db_filename))
      return TRUE;
    fn_list = fn_list->next;
  }
  return FALSE;
} /* check_bi_db_filename */

#if 0
static void server_list(request_rec *r)
{
  server_rec *s;

  if (!r)
    return;

  s = r->connection->base_server;

  ap_rputs("<table border=" TABLE_BORDER " align=center>", r);

  while (s) {
    ap_rprintf(r, "<tr><td>%s</td></tr>\n", s->server_hostname);

    s = s->next;
  }

  ap_rputs("</table><br>\n", r);
}
#endif

int iprot_db_display(request_rec *r, const int user_details)
{
  server_rec *s = r->server;
  const char *iprot_version = IPROT_VERSION;
  const char *server_hostname = ap_get_server_name(r);

  DBM *db;
  datum db_key, db_nextkey, db_data;

  db_filename_list_ptr fn_list = NULL;

  r->no_cache = 1;
  r->content_type = "text/html";
  ap_send_http_header(r);
 
  ap_rprintf(r, "<html><header>\n<title>iProtect Admin %s "
	     "(version %s)</title>\n</header><body>\n", 
	     (user_details) ? "User Details" : "Display Database",
	     iprot_version);

  ap_rprintf(r, "<h1 align=center>iProtect Admin %s</h1>\n",
	     (user_details) ? "User Details" : "Display Database");
  ap_rprintf(r, "<h2 align=center>Server Name %s</h2>\n", server_hostname);
  ap_rputs("<p align=center><a href=\"iprot-admin\">"
	   "iProtect Admin Menu</a></p>\n", r);

  ap_rprintf(r, "<table border=" TABLE_BORDER " align=center>"
	     "<tr><td>Current Time</td>"
	     "<td>%s</td></tr>\n</table><br>\n", asc_time(r->request_time));

  ap_rputs("<table border=\"" TABLE_BORDER "\" align=center>\n", r);

  while (s) {
    prot_config_rec *prot_conf_rec =
      (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

    if (!check_db_filename(prot_conf_rec->filename, fn_list)) {
      /* if we've done this file already, skip it */
      if (prot_conf_rec->filename && strcmp(prot_conf_rec->filename, "")) {
	/* check for null or empty filenames, this should never happen */
	if (!(db = open_db(prot_conf_rec->filename,
			   IPROT_DB_FLAGS, 0664, r))) {
	  ap_rprintf(r, "<p align=center><font size=+1>Error opening database "
		     "%s: %s</font></p>\n</body>\n</html>",
		     prot_conf_rec->filename, strerror(errno));
	  return OK;
	}

	if (!add_db_filenames(prot_conf_rec->filename,
			      prot_conf_rec->block_ignore_filename,
			      &fn_list, r)) {
	  ap_rputs("<p align=center><font size=+1>"
		   "Error out of memory.</font></p>\n", r);
	  close_db(&db, r);
	  return OK;
	}

	ap_rprintf(r, "<tr><td align=right>server hostname:</td>"
		   "<td colspan=2>%s</td></tr>\n",
		   s->server_hostname);
	ap_rprintf(r, "<tr><td align=right>database file:</td>"
		   "<td colspan=2>%s</td></tr>\n",
		   prot_conf_rec->filename);

	ap_rputs("<tr><td>Target</td><td colspan=2>Server</td></tr>\n", r);

	db_key = dbm_firstkey(db);
	while (db_key.dptr) {
	  char *key = NULL, *user = NULL;
	  char *local_host = NULL, *remote_host = NULL;
	  char *successfulIPStr = "";
	  char *failedIPStr = "";
	  char *BlockIgnoreStr = "";
	  char *BWStr = "";
	  char *str_1 = NULL;
	  int count = 0;

	  db_data = dbm_fetch(db, db_key);
	  if (!new_str_from_datum(&db_key, &key, r)) {
	    char *err_str = strerror(errno);
	    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
	    ap_rprintf(r, "</table><br>\n<p align=center><font size=+1>%s"
		       "</font></p></body></html>\n", err_str);
	    close_db(&db, r);
	    return OK;
	  }

	  get_items(key, &str_1, &local_host);

	  if (str_1 && isipaddress(prot_conf_rec, str_1)) {
	    if (!user_details) {
	      remote_host = PSTRDUP(r->pool, str_1);
	      if (!remote_host ||
		  !get_data_strings(r, &db_data,
				    &successfulIPStr,
				    &BlockIgnoreStr,
				    NULL, NULL)) {
		char *err_str = strerror(errno);
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
		ap_rprintf(r, "</table><br>\n<p align=center><font size=+1>"
			   "%s</font></p></body>\n</html>\n", err_str);
		close_db(&db, r);
		return OK;
	      }

	      ap_rprintf(r, "<tr>\n<td>%s</td>\n<td colspan=2>%s</td></tr>\n",
			 remote_host, local_host);

	      count = atoi(successfulIPStr);
	      ap_rprintf(r, "<tr><td></td><td>%i Password%s"
			 "</TD><TD>expires</TD></TR>\n",
			 count, (count > 1 ? "s" : ""));
	      print_footprintStr(r, successfulIPStr, TRUE);

	      if (strcmp(BlockIgnoreStr, "")) {
		ap_rprintf(r, "<tr><td></td><td colspan=2>%s</td></tr>\n",
			   BlockIgnoreStr);
	      }
	    } /* if (!user_details) */
	  } else { /* target is ip address */
	    if (str_1) {
	      user = PSTRDUP(r->pool, str_1);
	      if (!user ||
		  !get_data_strings(r, &db_data,
				    &successfulIPStr,
				    &failedIPStr,
				    &BlockIgnoreStr,
				    &BWStr)) {
		/* out of memory */
		char *err_str = strerror(errno);
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
		ap_rprintf(r, "</table><br>\n<p align=center><font size=+1>"
			   "%s</font></p>\n</body>\n</html>\n", err_str);
		close_db(&db, r);
		return OK;
	      }

	      if (strcmp(user, UPDATED_KEY)) {
		if ((user_details) &&
		    (strcmp(successfulIPStr, "") ||
		     strcmp(BlockIgnoreStr, "") ||
		     (strcmp(BWStr, "") && atol(BWStr) > (MBYTE / 100))))
		  ap_rprintf(r, "<tr>\n<td>%s</td>\n<td colspan=2>%s"
			     "</td>\n<tr>\n",
			     user, local_host);

		if (strcmp(successfulIPStr, "")) {
		  count = atoi(successfulIPStr);
		  ap_rprintf(r, "<tr><td></td><td>%i Successful IP%s"
			     "</td><td>expires</td></tr>\n",
			     count, (count > 1 ? "s" : ""));
		  print_footprintStr(r, successfulIPStr, TRUE);
		} /* successfulIPStr */

		if ((!user_details) && strcmp(failedIPStr, "")) {
		  count = atoi(failedIPStr);
		  ap_rprintf(r, "<tr><td></td><td>%i Failed IP%s"
			     "</td><td>expires</td></tr>\n",
			     count, (count > 1 ? "s" : ""));
		  print_footprintStr(r, failedIPStr, TRUE);
		} /* failedIPStr */

		if (strcmp(BlockIgnoreStr, "")) {
		  time_t timestamp;
		  char c;
		  /* this might not be portable, caution */
		  sscanf(BlockIgnoreStr, "%c:%i", &c, (int *)&timestamp);

		  if (c == 'B') {
		    ap_rprintf(r, "<tr><td></td><td>Blocked</td>"
			       "<td>%s</td></tr>\n",
			       (timestamp) ?
			       asc_time(timestamp) : "permanent");
		  } else {
		    if (c == 'I') {
		      ap_rprintf(r, "<tr><td></td><td>Ignored</td>"
				 "<td>%s</td></tr>\n",
				 (timestamp) ?
				 asc_time(timestamp) : "permanent");
		    } else {
		      ap_rprintf(r, "<tr><td></td>"
				 "<td colspan=2>%s</td></tr>\n",
				 BlockIgnoreStr);
		    }
		  }
		} /* BlockIgnoreStr */

		if (strcmp(BWStr, "")) {
		  int b;
		  char c;
		  time_t t;

		  if (sscanf(BWStr, "%i%c%i", &b, &c, (int *)&t) == 3) {
		    if (!user_details || b > (MBYTE / 100))
		      ap_rprintf(r, "<tr><td></td><td>%.2f Mbytes</td>"
				 "<td>%s</td></tr>\n",
				 ((double) b / (double) MBYTE), asc_time(t));
		  }
		} /* BWStr */
	      }
	    } /* if (strcmp ... */
	  } /* target is user name */

	  db_nextkey = dbm_nextkey(db);
	  db_key = db_nextkey;
	} /* while */

	ap_rputs("<tr><td colspan=3>&nbsp;</td></tr>\n", r);
	close_db(&db, r);
      } /* if (good db name) */
    } /* if not done already */

    s = s->next;
  } /* while (s) */

  ap_rputs("</table>\n</body>\n</html>\n", r);

  return OK;
} /* iprot_db_display */

static void assemble_footprint_str(footprint *footprint_list,
				   int count,
				   char **newFootprint,
				   const int footprintStr_len)
{
  int i;

  snprintf(*newFootprint, footprintStr_len, "%i%c", count, '?');
  for (i = 0; i < count; i++) {
    char buffer[128];

    snprintf(buffer, 128, "%s:%li;",
	     footprint_list[i].item,
	     footprint_list[i].timestamp);
    strncat(*newFootprint, buffer, footprintStr_len);
  }
} /* assemble_footprint_str */

static int print_hdr(request_rec *r)
{
  ap_rprintf(r, "<input type=\"hidden\" name=\"del_type\" value=\"%i\">\n",
	     BLOCK_DELETE);
  ap_rputs("<table border=" TABLE_BORDER " align=center>\n", r);
  ap_rputs("<tr><td><b>Hostname</b></td>"
	   "<td><b>User Name or IP Address</b></td>"
	   "<td><b>Block Type</b></td>"
	   "<td><b>Block Expires</b></td>"
	   "<td><b>View/Edit</b></td></tr>\n", r);

  return TRUE;
} /* print_hdr */

static int add_block_ignore(request_rec *r,
			    DBM *block_ignore_db, DBM *iprot_db,
			    const char *target, const char *server_hostname,
			    const char *block_ignore,
			    const int days, const int hours)
{
  server_rec *s = r->server;
  char *DataStr = NULL;

  prot_config_rec *config_rec =	/* module config rec */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  char *expire_time = (char *) PALLOC(r->pool, 14);
  char *BlockIgnoreStr = (char *) PALLOC(r->pool, 16);	/* U:1033423048 */
  if (!expire_time || !BlockIgnoreStr) { /* out of memory */
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return FALSE;
  }

  if (days || hours)
    snprintf(expire_time, 13, "%li",
	     ((days * (24 * (60 * 60))) + (hours * (60 * 60))) +
	     r->request_time);
  else
    strcpy(expire_time, "0");

#ifdef DEBUG
  ap_rprintf(r, "<p>\n");
  ap_rprintf(r, "target is: '%s'<br>\n", target);
  ap_rprintf(r, "block ignore is: '%s'<br>\n", block_ignore);
  ap_rprintf(r, "days is: '%i'<br>\n", days);
  ap_rprintf(r, "hours is: '%i'<br>\n", hours);
  ap_rprintf(r, "expire time is '%s'<br>\n", expire_time);
#endif

  strncpy(BlockIgnoreStr, block_ignore, 15);
  strncat(BlockIgnoreStr, ":", 15);
  strncat(BlockIgnoreStr, expire_time, 15);

#ifdef DEBUG
  ap_rprintf(r, "BlockIgnoreStr is '%s'<br>\n", BlockIgnoreStr);
#endif

  if (isipaddress(config_rec, target)) {
#ifdef DEBUG
    ap_rputs("target is an ip address<br>\n", r);
#endif
    /* get_data_strings(r, &d, 2, &SuccessfulIPStr, &str, NULL); */
    DataStr = combine_data_strings(r, "", BlockIgnoreStr, NULL, NULL);
  } else {
#ifdef DEBUG
    ap_rputs("target is a user name<br>\n", r);
#endif
    /* get_data_strings(r, &d, 3,
       &SuccessfulIPStr, &FailedIPStr, &str); */
    DataStr = combine_data_strings(r, "", "", BlockIgnoreStr, "");
  }

  if (!DataStr) {	 /* out of memory */
    char *err_str = strerror(errno);
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
    ap_rprintf(r, "<p align=center><font size=+1>%s</font></p>\n", err_str);
    return FALSE;
  }

#ifdef DEBUG
  ap_rprintf(r, "DataStr is '%s'<br>\n</p>\n", DataStr);
#endif

  if (!store_record(iprot_db, server_hostname, target, DataStr, r) ||
      !store_record(block_ignore_db, server_hostname, target,
		    BlockIgnoreStr, r)) {
    ap_rprintf(r, "<p align=center><font size=+1>"
	       "Error storing database record.</font></p>\n");
    return FALSE;
  }

  return TRUE;
} /* add_block_ignore */

static int view_block(request_rec *r, server_rec *s,
		      char *IPStr,
		      const unsigned int threshold,
		      const char *target,
		      const char *hostname,
		      const char *reason,
		      const int list,
		      int *hdr_printed)
{
  char *footprintStr;
  footprint *footprint_list;
  int footprint_n;
  int footprintStr_len;
  int count = 0;
  time_t exp; /* also used for bw block timestamp */
  int iprot_block = FALSE;
  int bw_block = FALSE;
  int total_bytes_sent = 0;

  /* Get the config rec assosiated with the server_rec s we were passed. */
  prot_config_rec *prot_conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  if (IPStr[0] == 'B') {
    exp = (time_t) atol(strchr(IPStr, ':') + 1);
  } else {
    if (IPStr[0] == 'I') {
      exp = (time_t) atol(strchr(IPStr, ':') + 1);
    } else {
      iprot_block = TRUE;

      if (!strcmp(reason, "bandwidth block")) {
	/* must match string in caller */
	char flag_char;

	bw_block = TRUE;
	if (sscanf(IPStr, "%i%c%i", &total_bytes_sent,
		   &flag_char, (int *)&exp) != 3) {
	  ap_rputs("<p align=center><font size=+1>error in view_block()"
		   " params</font></p>\n </body>\n</html>\n", r);
	  return -1;
	}
      } else {
	footprint_n = threshold + 2;
	footprintStr_len = strlen(IPStr) + 128;
					      
	if (!(footprintStr =
	      (char *) PALLOC(r->pool, footprintStr_len)) ||
	    !(footprint_list =
	      (footprint *) PALLOC(r->pool, sizeof(footprint) *
				   footprint_n))) {
	  char *err_str = strerror(errno);
	  ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
	  ap_rprintf(r, "<p align=center><font size=+1>%s</font></p>\n"
		     "</body>\n</html>\n", err_str);
	  return -1;
	}

	/* this will prune the list of expired entries */
	if ((count = get_footprint_list(IPStr,
					footprint_list,
					r->request_time,
					&exp)) >= threshold) {
	  assemble_footprint_str(footprint_list, count,
				 &footprintStr, footprintStr_len);
	}
      }
    }
  }

  if ((count >= threshold) ||
      (!diff_day(exp, r->request_time) &&
       (total_bytes_sent > (threshold * MBYTE))) ||
      !iprot_block) { /* There's no check for expired bw blocks??? */
    if (list) { /* print one line in the list of blocks */
      if (hdr_printed && !*hdr_printed)
	*hdr_printed = print_hdr(r);

      ap_rprintf(r, "<tr><td>%s</td>\n<td>%s</td>\n", hostname, target);
      if (bw_block) {
	  ap_rprintf(r, "<td>%s</td>\n<td>%s</td>\n",
		     reason, asc_time(exp));
      } else {
	if (iprot_block) {
	  ap_rprintf(r, "<td>%s</td>\n<td>%s</td>\n",
		     reason, asc_time(exp));
	} else {
	  if (IPStr[0] == 'B')
	    ap_rputs("<td>user placed block</td>\n", r);
	  else
	    ap_rputs("<td>user placed ignore</td>\n", r);
	  if (!exp)
	    ap_rputs("<td>permanent</td>\n", r);
	  else
	    ap_rprintf(r, "<td>%s</td>\n", asc_time(exp));
	}
      }
 
      ap_rprintf(r, "<td align=center><a href=\"iprot-admin?"
		 "p=block-detail&t=%s&h=%s\">****</a></td></tr>\n",
		 target, hostname);
    } else { /* print block details */
      ap_rputs("<table border=" TABLE_BORDER " align=center>\n", r);
      if (iprot_block) {
	if (bw_block) {
	  ap_rprintf(r, "<tr><td colspan=2><b>User %s blocked for "
		     "bandwidth use.</b></td></tr>\n",
		     target);

	  ap_rprintf(r, "<tr><td colspan=2><b>%.2f MBytes on %s."
		     "</b></td></tr>\n",
		     ((double) total_bytes_sent / (double) MBYTE),
		     asc_time(exp));
	} else {
	  ap_rprintf(r, "<tr><td colspan=2><b>%s %s blocked for "
		     "%s (%i).</b></td></tr>\n",
		     (!strcmp(reason, "password hacking")) ? "IP" : "User",
		     target, reason, count);
	  ap_rprintf(r, "<tr><td colspan=2><b>Expires at %s."
		     "</b></td></tr>\n", asc_time(exp));

	  ap_rprintf(r, "<tr><td><b>%s</b></td>"
		     "<td><b>Expires at</b></td></tr>\n", 
		     (!strcmp(reason, "password hacking")) ?
		     "Password" : "IP");

	  print_footprintStr(r, footprintStr, FALSE);
	} /* not a bandwidth block */

	ap_rprintf(r, "<tr><td align=center><a href=\"iprot-admin?"
		   "p=view-edit&t=%s&h=%s&a=c-del-b\"><font color=red>"
		   "Delete Block</font></a></td>\n",
		   target, hostname);
	ap_rprintf(r, "<td align=center><a href=\"iprot-admin?"
		   "p=view-edit&t=%s&h=%s&a=c-perm\"><font color=red>"
		   "Make Permanent</font></a></td></tr>\n",
		   target, hostname);
      } else { /* user block/ignore */
	ap_rprintf(r, "<tr><td colspan=2><b>User placed %s on %s for %s."
		   "</b></td></tr>\n",
		   (IPStr[0] == 'B') ? "block" : "ignore", target, hostname);
	if (exp)
	  ap_rprintf(r, "<tr><td colspan=2><b>Expires at %s."
		     "</b></td></tr>\n", asc_time(exp));
	else
	  ap_rputs("<tr><td><b>Permanent.</b></td></tr>\n", r);
	ap_rprintf(r, "<tr><td align=center><a href=\"iprot-admin?"
		   "p=view-edit&t=%s&h=%s&a=c-del-bi\">"
		   "<font color=red>Delete Block</font></a></td>\n",
		   target, hostname);
      }
      ap_rputs("</table>\n", r);
    }

    return TRUE;
  }

  return FALSE;
} /* view_block */

static int get_get_param(request_rec *r, const char *name, char **value)
{
# define N_MATCHES 2
  regmatch_t pmatch[N_MATCHES];
  regex_t *regex;
  char *args;
# define REGEX_STR_LEN 32
  char regex_str[REGEX_STR_LEN];

  snprintf(regex_str, REGEX_STR_LEN, "%s=([^&]*)", name);

  if (!(args = (char *) PSTRDUP(r->pool, r->args)) ||
      !(regex = ap_pregcomp(r->pool, regex_str, REG_EXTENDED))) {
    char *err_str = strerror(errno);
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
    ap_rprintf(r, "<p><b>%s</b></p>\n</body></html>\n", err_str);
    return FALSE;
  }

  if (!ap_regexec(regex, r->args, N_MATCHES, pmatch, 0)) {
    *value = &args[pmatch[1].rm_so];
    args[pmatch[1].rm_eo] = (char) NULL;
    ap_unescape_url((char*) *value);
  } else {
    *value = NULL;
  }

  ap_pregfree(r->pool, regex);
  return TRUE;
} /* get_get_param */

static int get_block_params(request_rec *r,
			    char **target, char **hostname)
{
  if (!get_get_param(r, "t", target) ||
      !get_get_param(r, "h", hostname))
    return FALSE; /* error */

  return (*target && *hostname);
} /* get_block_params */

static int get_host_db_filenames(request_rec *r, const char* hostname,
				 int *threshold, int *failed_threshold,
				 int *max_bytes_user,
				 char **db_file, char **b_i_db_file)
{
  server_rec *s = r->server;
  prot_config_rec *prot_conf_rec;
  int all_hosts = -1;

  prot_conf_rec = (prot_config_rec *)
    GET_MODULE_CONFIG(s->module_config, &iprot_module);

  if (all_hosts == -1)
    all_hosts = prot_conf_rec->all_hosts_admin;

  if (threshold)
    *threshold = atoi(prot_conf_rec->threshold);
  if (failed_threshold)
    *failed_threshold = atoi(prot_conf_rec->failed_threshold);
  if (max_bytes_user)
    *max_bytes_user = atoi(prot_conf_rec->max_bytes_user);

  if (db_file) {
    *db_file = PSTRDUP(r->pool, prot_conf_rec->filename);
    if (!*db_file) {  /* out of memory */	  
      char *err_str = strerror(errno);
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
      ap_rprintf(r, "<p align=center><font size=+1>"
		 "%s</font></p>\n</body>\n</html>\n", err_str);
      return FALSE;
    }
  }

  if (b_i_db_file) {
    *b_i_db_file =
      PSTRDUP(r->pool, prot_conf_rec->block_ignore_filename);
    if (!*b_i_db_file) {  /* out of memory */	  
      char *err_str = strerror(errno);
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
      ap_rprintf(r, "<p align=center><font size=+1>"
		 "%s</font></p>\n</body>\n</html>\n", err_str);
      return FALSE;
    }
  }

  if (!strcmp(hostname, s->server_hostname))
    return TRUE;

  s = s->next;

  /* If all_hosts_admin look through the list of servers to find one
     matching this hostname and get the database file names. */
  if (all_hosts)
    while (s) {
      if (!strcmp(hostname, s->server_hostname)) {
	prot_conf_rec = (prot_config_rec *)
	  GET_MODULE_CONFIG(s->module_config, &iprot_module);

	if (threshold)
	  *threshold = atoi(prot_conf_rec->threshold);
	if (failed_threshold)
	  *failed_threshold = atoi(prot_conf_rec->failed_threshold);
	if (max_bytes_user)
	  *max_bytes_user = atoi(prot_conf_rec->max_bytes_user);

	if (db_file) {
	  *db_file = PSTRDUP(r->pool, prot_conf_rec->filename);
	  if (!*db_file) {  /* out of memory */	  
	    char *err_str = strerror(errno);
	    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
	    ap_rprintf(r, "<p align=center><font size=+1>"
		       "%s</font></p>\n</body>\n</html>\n", err_str);
	    return FALSE;
	  }
	}

	if (b_i_db_file) {
	  *b_i_db_file =
	    PSTRDUP(r->pool, prot_conf_rec->block_ignore_filename);
	  if (!*b_i_db_file) {  /* out of memory */	  
	    char *err_str = strerror(errno);
	    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
	    ap_rprintf(r, "<p align=center><font size=+1>"
		       "%s</font></p>\n</body>\n</html>\n", err_str);
	    return FALSE;
	  }
	}

	break;
      } /*if */

      s = s->next;
    } /* while */

  return TRUE;
} /* get_host_db_filenames */

static int iprot_block_detail(request_rec *r) /* p=block-detail */
{
  server_rec *s = r->server;
  const char *server_hostname = ap_get_server_name(r);
  char *target = NULL;
  char *hostname = NULL;
  char *successfulIPStr = "";
  char *failedIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";
  int block_printed = FALSE;
  int result;

  DBM *db;
  datum db_data;

  prot_config_rec *prot_conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  int threshold;
  int failed_threshold;
  unsigned int max_bytes_user;
  char *db_file;
  char *b_i_db_file;

  r->no_cache = 1;
  r->content_type = "text/html";
  ap_send_http_header(r);
 
  ap_rputs("<html>\n<header>\n"
	   "<title>View/Edit iProtect Block</title>\n"
	   "</header>\n"
	   "<body>\n"
	   "<p align=center><font size=+3>View/Edit iProtect Block"
	   "</font>\n<br>" COPYRIGHT_NOTICE "\n<br><a href=\""
	   SUPPORT_MAIL_URL "\">Email Support</a></p>\n", r);

  /*if (!get_block_params(r, &target, &hostname, &db_file, &b_i_db_file)) {*/
  if (!get_block_params(r, &target, &hostname)) {
    ap_rputs("<p align=center><font size=+1>"
	     "Error in iprot_block_detail() parameters."
	     "</font></p></body></html>\n", r);
    return OK;
  }

  if (!prot_conf_rec->all_hosts_admin &&
      strcmp(server_hostname, hostname)) {
    /* Someone snuck in a different hostname. We can't check this if
       all_hosts_admin is true. */
    ap_rputs("<p align=center><font size=+1>"
	     "Error hostnames don't match in iprot_block_detail()."
	     "</font></p>\n</body></html>\n", r);
    return OK;
  }

  if (!prot_conf_rec->all_hosts_admin)
    ap_rprintf(r, "<p align=center><a href=\"iprot-admin\">"
	       "iProtect Admin Menu</a>\n"
	       "<br><font size=+1>Server: %s</font></p>\n", hostname);
  ap_rprintf(r, "<table border=" TABLE_BORDER
	     " align=center><tr><td>Current Time</td>"
	     "<td>%s</td></tr>\n</table><br>\n", asc_time(r->request_time));

  if (!get_host_db_filenames(r, hostname,
			     &threshold, &failed_threshold,
			     &max_bytes_user,
			     &db_file, &b_i_db_file))
    return OK;

  if (!(db = open_db(db_file, IPROT_DB_FLAGS, 0664, r))) {
    ap_rprintf(r, "<p align=center><font size=+1>"
	       "Error opening database %s: %s (%s)</font></p>"
	       "</body>\n</html>\n\n",
	       db_file, strerror(errno), hostname);
    return OK;
  }

  get_record(db, &db_data, hostname, target, r);

  if (!db_data.dptr) {
    ap_rprintf(r, "<p align=center><font size=+1>"
	       "No record for %s at %s found.</font></p>\n"
	       "</body>\n</html>\n", target, hostname);
    close_db(&db, r);
    return OK;
  }

  if (isipaddress(prot_conf_rec, target)) { /* target is ip address */
    if (!get_data_strings(r, &db_data,
			  &successfulIPStr,
			  &BlockIgnoreStr,
			  NULL, NULL)) {
      char *err_str = strerror(errno);
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
      ap_rprintf(r, "<p align=center><font size=+1>%s</font></p>"
		 "</body></html>\n", err_str);
      close_db(&db, r);
      return OK;
    }

    if (strcmp(successfulIPStr, "")) {
      result = view_block(r, s, successfulIPStr,
			  threshold, target, hostname,
			  "password hacking", FALSE, NULL);
      if (result == -1)
      {
	close_db(&db, r);
	return OK; /* error in view_block */
      }

      if (block_printed == FALSE)
	block_printed = result;
    }

    if (strcmp(BlockIgnoreStr, "") && (BlockIgnoreStr[0] == 'B')) {
      /* don't show ignores */
        if ((result = view_block(r, s, BlockIgnoreStr,
			    threshold, target, hostname,
			    "user block ignore", FALSE, NULL)) == -1) {
	  close_db(&db, r);
	  return OK; /* error in view_block */
        }

      if (block_printed == FALSE)
	block_printed = result;
    }
  } /* target is ip address */ else { /* target is user */
    if (!get_data_strings(r, &db_data,
			  &successfulIPStr, &failedIPStr,
			  &BlockIgnoreStr, &BWStr)) {
      char *err_str = strerror(errno);
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
      ap_rprintf(r, "</table><br><p align=center><font size=+1>"
		 "%s</font></p></body></html>\n", err_str);
      close_db(&db, r);
      return OK;
    }

    if (strcmp(target, UPDATED_KEY)) {
      if (strcmp(successfulIPStr, "")) {
	result = view_block(r, s,
			    successfulIPStr, threshold,
			    target, hostname,
			    "password sharing", FALSE, NULL);
	if (result == -1)
        {
          close_db(&db, r);
	  return OK; /* error in view_block */
        }

	if (block_printed == FALSE)
	  block_printed = result;
      }

      if (strcmp(failedIPStr, "")) {
	if ((result = view_block(r, s,
				 failedIPStr, failed_threshold,
				 target, hostname,
				 "failed login attempts",
				 FALSE, NULL)) == -1) {
	  close_db(&db, r);
	  return OK; /* error in view_block */
	}
	
	if (block_printed == FALSE)
	  block_printed = result;
      }

      if (strcmp(BlockIgnoreStr, "") && (BlockIgnoreStr[0] == 'B')) {
	if ((result = view_block(r, s, BlockIgnoreStr,
			    threshold, target, hostname,
				 "user block ignore", FALSE, NULL)) == -1) {
	  close_db(&db, r);
	  return OK; /* error in view_block */
	}

	if (block_printed == FALSE)
	  block_printed = result;
      }

      if (strcmp(BWStr, "")) {
	if ((result = view_block(r, s, BWStr,
				 atoi(prot_conf_rec->max_bytes_user),
				 target, hostname,
				 "bandwidth block", FALSE, NULL)) == -1) {
	  close_db(&db, r);
	  return OK; /* error in view_block */
	}

	if (block_printed == FALSE)
	  block_printed = result;
      }
    } /* if (strcmp ... */
  } /* target is user name */

  if (!block_printed) {
    ap_rprintf(r, "<p align=center><font size=+1>Block for %s has expired."
	       "</font></b></p>\n", target);
  }

  ap_rputs("</body></html>\n", r);
  close_db(&db, r);
  return OK;
} /* iprot_block_detail */

/* List of blocks ("View/Edit iProtect Blocks"). */
static int view_blocks_form(request_rec *r)
{
  server_rec *s = r->server;
  const char *server_hostname = ap_get_server_name(r);

  int hdr_printed = FALSE;
  int all_hosts = -1;
  db_filename_list_ptr fn_list = NULL;

  ap_rputs("<br><table border=" TABLE_BORDER " align=center>\n", r);
  ap_rprintf(r, "<tr><td><b>Current Time</b></td>"
	     "<td>%s</td></tr>\n", asc_time(r->request_time));
  ap_rputs("</table><br>\n", r);

  while (s) {
    prot_config_rec *prot_conf_rec =
      (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);
    int threshold = atoi(prot_conf_rec->threshold);
    int failed_threshold = atoi(prot_conf_rec->failed_threshold);

    if (all_hosts == -1) /* might change even if filename doesn't */
      all_hosts = prot_conf_rec->all_hosts_admin;

    if (!check_db_filename(prot_conf_rec->filename, fn_list)) {
      DBM *db = NULL;
      datum db_key, db_nextkey, db_data;

      /* if we've done this file already, skip it */
      if (prot_conf_rec->filename && strcmp(prot_conf_rec->filename, "")) {
	/* check for null or empty filenames, this should never happen */
	if (!(db = open_db(prot_conf_rec->filename,
			   IPROT_DB_FLAGS, 0664, r))) {
	  ap_rprintf(r, "<p align=center><font size=+1>"
		     "Error opening database %s: %s</font></p>\n"
		     "</body>\n</html>\n",
		     prot_conf_rec->filename, strerror(errno));
	  return OK;
	}
	
	if (!add_db_filenames(prot_conf_rec->filename,
			      prot_conf_rec->block_ignore_filename,
			      &fn_list, r)) {
	  ap_rputs("<p align=center><font size=+1>"
		   "Error out of memory.</font></p>\n", r);
	  close_db(&db, r);
	  return OK;
	}

	db_key = dbm_firstkey(db);
	while (db_key.dptr) {
	  char *key = NULL;
	  char *user = NULL, *local_host = NULL, *remote_host = NULL;
	  char *successfulIPStr = "";
	  char *failedIPStr = "";
	  char *BlockIgnoreStr = "";
	  char *BWStr = "";
	  char *str_1 = NULL;
	  int target_printed = FALSE;

	  db_data = dbm_fetch(db, db_key);
	  /* error check ?? */

	  if (!new_str_from_datum(&db_key, &key, r)) {
	    char *err_str = strerror(errno);
	    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
	    ap_rprintf(r, "<p align=center><font size=+1>%s</font></p>"
		       "</body></html>\n", err_str);
	    close_db(&db, r);
	    return OK;
	  }

	  get_items(key, &str_1, &local_host);

	  /* Only display records for this server unless all_hosts_admin
	     flag is set. */
	  if ((all_hosts) ||
	      (local_host && !strcmp(server_hostname, local_host))) {

	    if (str_1 && isipaddress(prot_conf_rec, str_1)) {
	      /* target is an ip address */
	      if (!(remote_host = PSTRDUP(r->pool, str_1)) ||
		  !get_data_strings(r, &db_data, &successfulIPStr,
				    &BlockIgnoreStr, NULL, NULL))	{
		char *err_str = strerror(errno);
		close_db(&db, r);
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
		ap_rprintf(r, "<p align=center><font size=+1>%s</font></p>"
			   "</body></html>\n", err_str);
		close_db(&db, r);
		return OK;
	      }

	      /* check for user blocks */
	      if (strcmp(successfulIPStr, "")) {
		if ((target_printed = view_block(r, s,
						 successfulIPStr, threshold,
						 remote_host, local_host,
						 "password hacking",
						 TRUE, &hdr_printed)) == -1) {
		  close_db(&db, r);
		  return OK; /* error in view_block() */
		}
	      }

	      if (strcmp(BlockIgnoreStr, "") && (BlockIgnoreStr[0] == 'B')) {
		/* don't show ignores */
		if ((target_printed = view_block(r, s,
						 BlockIgnoreStr, threshold,
						 remote_host, local_host,
						 "user block ignore",
						 TRUE, &hdr_printed)) == -1) {
		  close_db(&db, r);
		  return OK; /* error in view_block() */
		}
	      }
	    } /* target is ip address */ else { /* target is user name */
	      if (str_1) {
		if (!(user = PSTRDUP(r->pool, str_1)) ||
		    !get_data_strings(r, &db_data,
				      &successfulIPStr, &failedIPStr,
				      &BlockIgnoreStr, &BWStr))	{
		  char *err_str = strerror(errno);
		  ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", err_str);
		  ap_rprintf(r, "</table><br>\n<p align=center><font size=+1>"
			     "%s</font></p>\n</body></html>\n", err_str);
		  close_db(&db, r);
		  return OK;
		}

		if (strcmp(user, UPDATED_KEY)) {
		  if (strcmp(successfulIPStr, "")) {
		    if ((target_printed = view_block(r, s,
						     successfulIPStr,
						     threshold,
						     user, local_host,
						     "password sharing",
						     TRUE, &hdr_printed)) ==
			-1) {
		      close_db(&db, r);
		      return OK; /* error in view_block() */
		    }
		  } /* if (successfulIPStr) */

		  if (strcmp(failedIPStr, "")) {
		    if ((target_printed = view_block(r, s,
						     failedIPStr,
						     failed_threshold,
						     user, local_host,
						     "failed login attempts",
						     TRUE, &hdr_printed)) ==
			-1) {
		      close_db(&db, r);
		      return OK; /* error in view_block() */
		    }
		  } /* if (failedIPStr) */

		  if (strcmp(BlockIgnoreStr, "") &&
		      (BlockIgnoreStr[0] == 'B')) {
		    if ((target_printed = view_block(r, s,
						     BlockIgnoreStr, threshold,
						     user, local_host,
						     "user block ignore",
						     TRUE, &hdr_printed)) ==
			-1) {
		      close_db(&db, r);
		      return OK; /* error in view_block() */
		    }
		  }

		  if (strcmp(BWStr, "")) {
		    if ((target_printed =
			 view_block(r, s,
				    BWStr, atoi(prot_conf_rec->max_bytes_user),
				    user, local_host,
				    "bandwidth block",
				    /* must match string in view_block() */
				    TRUE, &hdr_printed)) == -1) {
		      close_db(&db, r);
		      return OK; /* error in view_block() */
		    }
		  }
		}
	      }
	    } /* target is user name */
	  } /* record is for this host */
	    
	  db_nextkey = dbm_nextkey(db);
	  db_key = db_nextkey;
	} /* while */

	close_db(&db, r);
      } /* if (good db name) */
    } /* if not done already */

    s = s->next;
  } /* while (s) */

  ap_rputs("</table>\n", r);

  if (!hdr_printed) {
    ap_rprintf(r, "<p align=center><font size=+1>"
	       "No blocks found.</font></p>\n");
  }

  return OK;
} /* view_blocks_form */

static int open_iprot_dbs(request_rec *r, const char *hostname,
			  DBM **block_ignore_db, DBM **iprot_db)
{
  char *db_file = NULL;
  char *b_i_db_file = NULL;

  if (!get_host_db_filenames(r, hostname,
			     NULL, NULL, NULL,
			     &db_file, &b_i_db_file))
    return FALSE;

  if (!(*block_ignore_db = open_db(b_i_db_file,
				  IPROT_DB_FLAGS, 0664, r))) {
    ap_rprintf(r, "<p align=center><font size=+1>"
	       "Error opening database %s: %s</font></p>\n",
	       b_i_db_file, strerror(errno));
    if (*block_ignore_db)
      close_db(block_ignore_db, r);
    return FALSE;
  }

  if (!(*iprot_db = open_db(db_file,
			   IPROT_DB_FLAGS, 0664, r))) {
    close_db(block_ignore_db, r);
    ap_rprintf(r, "<p align=center><font size=+1>"
	       "Error opening database %s: %s</font></p>\n",
	       db_file, strerror(errno));
    if (*block_ignore_db)
      close_db(block_ignore_db, r);
    if(*iprot_db)
      dbm_close(*iprot_db);
    return FALSE;
  }

  return TRUE;
} /* open_iprot_dbs */

static void close_iprot_dbs(request_rec *r, 
			    DBM **block_ignore_db,
			    DBM **iprot_db)
{
  if (*block_ignore_db)
    close_db(block_ignore_db, r);
  if (*iprot_db)
    close_db(iprot_db, r);
} /* close_iprot_dbs */

static int delete_block_ignore_callback(void *data,
					const char *key,
					const char *value)
{
  callback_data *cbd = (callback_data *) data;
  DBM *iprot_db;
  DBM *block_ignore_db;

#ifdef DEBUG
  ap_rprintf(cbd->r, "key is: '%s', value is '%s'<br>\n", key, value);
#endif

  if (value && !strcmp(value, "delete")) {
    char *p, *target, *hostname;
    char *k = PSTRDUP(cbd->r->pool, key);

    if (!k) {  /* out of memory */
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, cbd->r, "%s", strerror(errno));
      cbd->result = FALSE;
      return FALSE;
    }

    if ((p = strchr(k, '?')) != NULL) {
      p[0] = 0;
      target = k;
      hostname = p + 1;
#ifdef DEBUG
      ap_rprintf(cbd->r, "deleting: target is '%s', "
		 "hostname is '%s'<br>\n",
		 target, hostname);
#endif

      if ((cbd->del_type == BLOCK_IGNORE_DELETE) ||
	  (cbd->del_type == BLOCK_DELETE)) {
	if (!open_iprot_dbs(cbd->r, hostname,
			    &block_ignore_db, &iprot_db))
	  return FALSE;

	delete_block_ignore(cbd->r, block_ignore_db, iprot_db,
			    hostname, target, cbd->del_type);
	/* ignore any error and continue */

	close_iprot_dbs(cbd->r, &block_ignore_db, &iprot_db);
      }
    }
  }

  cbd->result = TRUE;
  return TRUE;
} /* delete_block_ignore_callback */

void confirm_action(request_rec *r,
		    const char *action,
		    const char *target,
		    const char *hostname)
{
  ap_rputs("<table border=" TABLE_BORDER " align=center>\n", r);
  ap_rputs("<tr><td><font size=+1>\n", r);

  if (!strcmp(action, "c-del-b") || !strcmp(action, "c-del-bi")) {
    ap_rprintf(r, "Delete block on %s at %s "
	       "(<a href=\"iprot-admin?p=view-edit&t=%s&h=%s&a=%s\">yes</a>/"
	       "<a href=\"iprot-admin?p=block-detail&t=%s&h=%s\">no</a>)?",
	       target, hostname, target, hostname,
	       !strcmp(action, "c-del-b") ? "del-b" : "del-bi",
	       target, hostname);
  } else {
    if (!strcmp(action, "c-perm")) {
      ap_rprintf(r, "Make block on %s at %s permanent "
		 "(<a href=\"iprot-admin?p=view-edit&t=%s&h=%s&a=%s\">"
		 "yes</a>/"
		 "<a href=\"iprot-admin?p=block-detail&t=%s&h=%s\">"
		 "no</a>)?",
		 target, hostname, target, hostname, "perm",
		 target, hostname);
    }
  }

  ap_rputs("</font></p>\n</td></tr>\n</body></html>\n", r);
} /* confirm_action */

static int iprot_view_edit_blocks(request_rec *r) /* p=view-edit */
{
  server_rec *s = r->server;
  prot_config_rec *prot_conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);
  char *action;
  char *target;
  char *hostname;
  char *db_file = NULL;
  char *b_i_db_file = NULL;
  const char *server_hostname = ap_get_server_name(r);

  r->no_cache = 1;
  r->content_type = "text/html";
  ap_send_http_header(r);
 
  ap_rputs("<html><header>\n<title>View/Edit iProtect Blocks "
	     "(version " IPROT_VERSION ")</title>\n</header><body>\n", r);

  ap_rputs("<p align=center><font size=+3>"
	   "View/Edit iProtect Blocks</font>\n", r);
  ap_rputs("<br>" COPYRIGHT_NOTICE "\n", r);
  ap_rputs("<br><a href=\"" SUPPORT_MAIL_URL "\">Email Support</a></p>\n", r);

  ap_rputs("<p align=center><a href=\"iprot-admin\">"
	   "iProtect Admin Menu</a></p>\n", r);

  if (r->args) {
    if (get_block_params(r, &target, &hostname)) {
      /* if params are set we are not just viewing the list */
      if (!get_get_param(r, "a", &action)) {
	ap_rputs("<p align=center><font size=+1>"
		 "Error in iprot_view_edit_blocks()"
		 " parameters.</font></p></body></html>\n", r);
	return OK;
      }

      ap_rprintf(r, "<p align=center><font size=+1>"
		 "Server: %s</font></p>\n", hostname);

      if (!prot_conf_rec->all_hosts_admin &&
	  strcmp(server_hostname, hostname)) {
	/* Someone snuck in a different hostname. We can't check this
	   if all_hosts_admin is true. */
	ap_rputs("<p align=center><font size=+1>"
		 "Error hostnames don't match in "
		 "iprot_view_edit_blocks().</font></p>\n"
		 "</body></html>\n", r);
	return OK;
      }

      if (!strncmp(action, "c-", 2)) {
	confirm_action(r, action, target, hostname);
	return OK;
      }

      if (!get_host_db_filenames(r, hostname,
				 NULL, NULL, NULL,
				 &db_file, &b_i_db_file))
	return OK;

      if (!strncmp(action, "del", 3)) {
	DBM *block_ignore_db = NULL, *iprot_db = NULL;

	if (!(iprot_db = open_db(db_file,
				 IPROT_DB_FLAGS, 0664, r)) ||
	    (!strcmp(action, "del-bi") &&
	     !(block_ignore_db = open_db(b_i_db_file,
					 IPROT_DB_FLAGS, 0664, r)))
	    ) {
	  ap_rprintf(r, "<p align=center><font size=+1>"
		     "Error opening database %s: "
		     "%s</font></p></body></html>\n",
		     (iprot_db) ?
		     prot_conf_rec->block_ignore_filename :
		     prot_conf_rec->filename, strerror(errno));
	  if (iprot_db)
	    dbm_close(iprot_db);
	  if (block_ignore_db)
	    dbm_close(block_ignore_db);
	  return OK;
	}

	if (!strcmp(action, "del-bi"))
	  delete_block_ignore(r, block_ignore_db, iprot_db,
			      hostname, target, BLOCK_IGNORE_DELETE);
	else
	  delete_block_ignore(r, NULL, iprot_db,
			      hostname, target, BLOCK_DELETE);
        if (iprot_db)
	  dbm_close(iprot_db);
	if (block_ignore_db)
	  dbm_close(block_ignore_db);

	ap_rprintf(r, "<p align=center><font size=+1>"
		   "Block for %s at %s deleted.</font></p>"
		   "</body></html>\n", target, hostname);
      } else {
	if (!strcmp(action, "perm")) {
	  DBM *block_ignore_db = NULL, *iprot_db = NULL;

	  if (!(iprot_db = open_db(db_file,
				   IPROT_DB_FLAGS, 0664, r)) ||
	      !(block_ignore_db = open_db(b_i_db_file,
					  IPROT_DB_FLAGS, 0664, r))) {
	    ap_rprintf(r, "<p align=center><font size=+1>"
		       "Error opening database %s: "
		       "%s</font></p></body></html>\n",
		       prot_conf_rec->filename, strerror(errno));
	    if (iprot_db)
	      dbm_close(iprot_db);
	    if (block_ignore_db)
	      dbm_close(block_ignore_db);
	    return OK;
	  }

	  if (!add_block_ignore(r, block_ignore_db, iprot_db,
				target, hostname, "B", 0, 0)) {
	    ap_rprintf(r, "<p align=center><font size=+1>"
		       "Error placing block: %s</font></p>"
		       "</body></html>\n",
		       strerror(errno));
	    return OK;
	    if (iprot_db)
	      dbm_close(iprot_db);
	    if (block_ignore_db)
	      dbm_close(block_ignore_db);
	  }
	} else {
	  ap_rputs("<p align=center><font size=+1>"
		   "Error: undefined action in "
		   "iprot_view_edit_blocks()."
		   "</b></p>\n</body></html>\n", r);
	  return OK;
	}
      }
    } /* if (!strcmp(page, "view-edit")) */
  } /* if (r->args) */

  /* this does the list of blocks */
  view_blocks_form(r);

  ap_rputs("<p align=center><a href=\"iprot-admin\">"
	   "iProtect Admin Menu</a></p>\n", r);
  ap_rputs("</body>\n</html>\n", r);

  return OK;
} /* iprot_view_edit_blocks */

static void virt_server_menu(request_rec *r, int i)
{
  server_rec *s = r->server;

  ap_rprintf(r, "<select name=\"server_%i\" size=\"1\">\n", i);

  ap_rprintf(r, "  <option value=\"all-servers\" selected>"
	     "- all servers -</option>\n");

  while (s) {
    ap_rprintf(r, "  <option value=\"%s\">%s</option>\n",
	       s->server_hostname, s->server_hostname);
    s = s->next;
  }

  ap_rprintf(r, "</select>\n");
} /* virt_server_menu */

static void print_table(request_rec *r, const char* title, table *t)
{
  array_header *arr;
  table_entry *elts;
  int i;

  if (!t) return;

  arr = ap_table_elts(t);
  elts = (table_entry *) arr->elts;

  if (arr->nelts > 0)
    for (i = 0; i < arr->nelts; ++i) {
      if (i == 0)
	ap_rprintf(r, "<tr><td>%s</td>", title);
      else
	ap_rprintf(r, "<tr><td></td>");

      ap_rprintf(r, "<td align=right>%s</td></tr>\n", elts[i].key);
    }
  else
    ap_rprintf(r, "<tr><td>%s</td><td align=right>&nbsp;</td></tr>", title);
} /* print_table */

static void server_configuration(request_rec *r)
{
  server_rec *s = r->server;

  int threshold;
  int compareN;
  long auth_timeout;	/* long to match time_t */
  long access_timeout;
  int failed_threshold;
  int failed_compareN;
  long failed_timeout;
  unsigned int max_bytes_user;
  prot_config_rec *rec = NULL;
  int all_hosts = -1;

#if 0
  server_list(r);
  ap_rputs("<p align=center>next</p>\n", r);
  server_list(r->next);
  ap_rputs("<p align=center>prev</p>\n", r);
  server_list(r->prev);
  ap_rputs("<p align=center>main</p>\n", r);
  server_list(r->main);
#endif

  while (s) {
    prot_config_rec *prot_conf_rec =
      (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);
    const char *server_hostname = s->server_hostname;

    if (!rec)
      rec = prot_conf_rec;
    if (all_hosts == -1) /* set this on the first server record */
      all_hosts = prot_conf_rec->all_hosts_admin;

    threshold = atoi(prot_conf_rec->threshold);
    compareN = atoi(prot_conf_rec->compareN);
    auth_timeout = atol(prot_conf_rec->auth_timeout);
    access_timeout = atol(prot_conf_rec->access_timeout);
    failed_threshold = atoi(prot_conf_rec->failed_threshold);
    failed_compareN = atoi(prot_conf_rec->failed_compareN);
    failed_timeout = atoi(prot_conf_rec->failed_timeout);
    max_bytes_user = atoi(prot_conf_rec->max_bytes_user);

    ap_rputs("<table border=" TABLE_BORDER " align=center>\n", r);
    ap_rprintf(r, "<tr><td colspan=2 align=center>"
	       "<big>Server: %s</big></td></tr>\n",
	       server_hostname);
    ap_rprintf(r, "<tr><td>IProtThreshold</td><td align=right>%i</td>"
	       "</tr>\n", threshold);
    ap_rprintf(r, "<tr><td>IProtAuthTimeout</td><td align=right>%li "
	       "second%s</td></tr>\n",
	       auth_timeout, Print_Plural(auth_timeout));
    ap_rprintf(r, "<tr><td>IProtAccessTimeout</td><td align=right>%li "
	       "hour%s</td></tr>\n",
	       access_timeout, Print_Plural(access_timeout));
    ap_rprintf(r, "<tr><td>IProtCompareN</td><td align=right>%i</td>"
	       "</tr>\n", compareN);
    ap_rprintf(r, "<tr><td>IProtEmail</td><td align=right>%s</td>"
	       "</tr>\n", (prot_conf_rec->email) ?
	       prot_conf_rec->email : "&nbsp;");
    ap_rprintf(r, "<tr><td>IProtFailedThreshold</td><td align=right>%i</td>"
	       "</tr>\n", failed_threshold);
    ap_rprintf(r, "<tr><td>IProtFailedTimeout</td><td align=right>%li "
	       "second%s</td></tr>\n",
	       failed_timeout, Print_Plural(failed_timeout));
    ap_rprintf(r, "<tr><td>IProtFailedCompareN</td><td align=right>%i</td>"
	       "</tr>\n", failed_compareN);
    ap_rprintf(r, "<tr><td>IProtNotifyUser</td><td align=right>%s</td>"
	       "</tr>\n", On_Off(prot_conf_rec->notifyuser));
    ap_rprintf(r, "<tr><td>IProtNotifyLogin</td><td align=right>%s</td>"
	       "</tr>\n", On_Off(prot_conf_rec->notifylogin));
    ap_rprintf(r, "<tr><td>IProtAbuseStatusReturn</td><td align=right>%i</td>"
	       "</tr>\n", prot_conf_rec->abuse_status_return);
    ap_rprintf(r, "<tr><td>IProtAbuseRedirectURL</td><td>%s</td>"
	       "</tr>\n", (prot_conf_rec->abuse_redirect_url) ?
	       prot_conf_rec->abuse_redirect_url : "&nbsp;");
    ap_rprintf(r, "<tr><td>IProtAbuseEmail</td><td align=right>%s</td>"
	       "</tr>\n", (prot_conf_rec->abuse_email) ?
	       prot_conf_rec->abuse_email : "&nbsp;");
    ap_rprintf(r, "<tr><td>IProtHackStatusReturn</td><td align=right>%i</td>"
	       "</tr>\n", prot_conf_rec->hack_status_return);
    ap_rprintf(r, "<tr><td>IProtHackRedirectURL</td><td>%s</td>"
	       "</tr>\n", (prot_conf_rec->hack_redirect_url) ?
	       prot_conf_rec->hack_redirect_url : "&nbsp;");
    ap_rprintf(r, "<tr><td>IProtHackEmail</td><td align=right>%s</td>"
	       "</tr>\n", (prot_conf_rec->hack_email) ?
	       prot_conf_rec->hack_email : "&nbsp;");
    ap_rprintf(r, "<tr><td>IProtNotifyIP</td><td align=right>%s</td>"
	       "</tr>\n", On_Off(prot_conf_rec->notifyip));
    ap_rprintf(r, "<tr><td>IProtMaxBytesUser</td><td align=right>%iMB/day</td>"
	       "</tr>\n", max_bytes_user);
    ap_rprintf(r, "<tr><td>IProtBWTimeout</td><td align=right>%i hours</td>"
	       "</tr>\n", prot_conf_rec->bw_timeout);
    ap_rprintf(r, "<tr><td>IProtBWStatusReturn</td><td align=right>%i</td>"
	       "</tr>\n", prot_conf_rec->bw_status_return);
    ap_rprintf(r, "<tr><td>IProtBWRedirectURL</td><td>%s</td>"
	       "</tr>\n", (prot_conf_rec->bw_redirect_url) ?
	       prot_conf_rec->bw_redirect_url : "&nbsp;");
    ap_rprintf(r, "<tr><td>IProtBWEmail</td><td align=right>%s</td>"
	       "</tr>\n", (prot_conf_rec->bw_email) ?
	       prot_conf_rec->bw_email : "&nbsp;");
    ap_rprintf(r, "<tr><td>IProtNotifyBW</td><td align=right>%s</td>"
	       "</tr>\n", On_Off(prot_conf_rec->notifybw));
    ap_rprintf(r, "<tr><td>IProtEnable</td><td align=right>%s</td>"
	       "</tr>\n", On_Off(prot_conf_rec->enabled));
    ap_rprintf(r, "<tr><td>IProtNag</td><td align=right>%s</td>"
	       "</tr>\n", On_Off(prot_conf_rec->nag));
    ap_rprintf(r, "<tr><td>IProtExternalIP</td><td align=right>%s</td>"
	       "</tr>\n", (prot_conf_rec->external_progip) ?
	       prot_conf_rec->external_progip : "&nbsp;");
    ap_rprintf(r, "<tr><td>IProtExternalUser</td><td align=right>%s</td>"
	       "</tr>\n", (prot_conf_rec->external_proguser) ?
	       prot_conf_rec->external_proguser : "&nbsp;");
    print_table(r, "IprotIgnoreIP", prot_conf_rec->ignore_ips);
    print_table(r, "IProtIgnoreUser", prot_conf_rec->ignore_users);
    ap_rprintf(r, "<tr><td>IProtNoHEADReq</td><td align=right>%s</td>"
	       "</tr>\n", On_Off(prot_conf_rec->no_HEAD_req));
    ap_rprintf(r, "<tr><td>IProtAllHostsAdmin</td><td align=right>%s</td>"
	       "</tr>\n", On_Off(prot_conf_rec->all_hosts_admin));
    ap_rprintf(r, "<tr><td>IProtDBFile</td><td>%s</td>"
	       "</TR>\n", prot_conf_rec->filename);
    ap_rprintf(r, "<tr><td>IProtBlockIgnoreDBFile</td><td align=right>%s</td>"
	       "</tr>\n", prot_conf_rec->block_ignore_filename);
    ap_rputs("</table><br>\n", r);

    if (all_hosts)
      s = s->next;
    else
      s = NULL;
  } /* while */
} /* server_configuration */

static int iprot_configuration(request_rec *r)
{
  const char *server_hostname = ap_get_server_name(r);

  r->no_cache = 1;
  r->content_type = "text/html";
  ap_send_http_header(r);
 
  ap_rputs("<HTML><HEADER>\n", r);
  ap_rputs("<TITLE>iProtect Configuration</TITLE>\n", r);
  ap_rputs("</HEADER><BODY>\n", r);

  ap_rprintf(r, "<p align=center><font size=+3>"
	     "iProtect Configuration for <b>%s</b></font>\n",
	     server_hostname);
  ap_rputs("<br>" COPYRIGHT_NOTICE "\n", r);
  ap_rputs("<br><a href=\"" SUPPORT_MAIL_URL "\">Email Support</a></p>\n", r);
  ap_rputs("<p align=center><a href=\"iprot-admin\">"
	   "iProtect Admin Menu</a></p>\n", r);

  ap_rputs("<table border=" TABLE_BORDER " align=center>\n", r);
  ap_rputs("<tr><td><big>iProtect Version</big></td><td align=right><big>"
	   IPROT_VERSION "</big></td></tr>\n", r);
  ap_rprintf(r, "<tr><td><big>Apache Release</big></td>"
	     "<td align=right><big>%i</big></td></tr>\n", APACHE_RELEASE);
  ap_rputs("</table border><br>\n", r);

  server_configuration(r);

  ap_rputs("<p align=center><a href=\"iprot-admin\">"
	   "iProtect Admin Menu</a></p>\n", r);
  ap_rputs("</body>\n</html>\n", r);
  return OK;
} /* iprot_configuration */

/* user added blocks and ignores are added or deleted here */
static int process_block_ignore_form(request_rec *r, table *post_params_table)
{
  server_rec *s = r->server;
  const char *server_hostname = ap_get_server_name(r);
  int i;
  callback_data cbd;
  DBM *iprot_db;
  DBM *block_ignore_db;

  prot_config_rec *prot_conf_rec =	/* module config rec */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  if (post_params_table && !ap_is_empty_table(post_params_table)) {
    char *server_str, *target_str, *block_ignore_str, *days_str, *hours_str;

    cbd.r = r;
    cbd.result = TRUE;
    cbd.del_type = BLOCK_IGNORE_DELETE; /* block ignore from */

#ifdef DEBUG
    ap_rprintf(r, "<p>\n");
#endif
    ap_table_do(delete_block_ignore_callback, &cbd, post_params_table, NULL);
#ifdef DEBUG
    ap_rprintf(r, "</p>\n");
#endif

    if (!cbd.result) 	/* error */
      return FALSE;

#   define TARGET_STR "target_%i"
#   define SERVER_STR "server_%i"
#   define BLOCK_IGNORE_STR "block_ignore_%i"
#   define DAYS_STR "days_%i"
#   define HOURS_STR "hours_%i"

    target_str = (char *) PALLOC(r->pool, strlen(TARGET_STR) + 4);
    server_str = (char *) PALLOC(r->pool, strlen(SERVER_STR) + 4);
    block_ignore_str =
      (char *) PALLOC(r->pool, strlen(BLOCK_IGNORE_STR) + 4);
    days_str = (char *) PALLOC(r->pool, strlen(DAYS_STR) + 4);
    hours_str = (char *) PALLOC(r->pool, strlen(HOURS_STR) + 4);

    if (!target_str || !server_str ||
	!block_ignore_str || !days_str || !hours_str) {
      /*out of memory */
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
      return FALSE;
    }

    for (i = 0; i < N_NEW_BLOCKS; i++) {
      char *target, *server, *block_ignore, *days, *hours;

      ap_snprintf(target_str, strlen(TARGET_STR), TARGET_STR, i);
      ap_snprintf(server_str, strlen(SERVER_STR), SERVER_STR, i);
      ap_snprintf(block_ignore_str, strlen(BLOCK_IGNORE_STR),
		  BLOCK_IGNORE_STR, i);
      ap_snprintf(days_str, strlen(DAYS_STR), DAYS_STR, i);
      ap_snprintf(hours_str, strlen(HOURS_STR), HOURS_STR, i);

      target =
	PSTRDUP(r->pool, ap_table_get(post_params_table, target_str));
      server =
	PSTRDUP(r->pool, ap_table_get(post_params_table, server_str));

      if (!target || !server) {	/*out of memory */
	ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
	return FALSE;
      }

      if (strcmp(target, "")) { /* target != "" */
	block_ignore =
	  PSTRDUP(r->pool, ap_table_get(post_params_table,
					block_ignore_str));
	days = PSTRDUP(r->pool, ap_table_get(post_params_table,
					     days_str));
	hours = PSTRDUP(r->pool, ap_table_get(post_params_table,
					      hours_str));

	if (!block_ignore || !days || !hours) {	 /*out of memory */
	  ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
	  return FALSE;
	}

	if (prot_conf_rec->all_hosts_admin) {
	  if (!strcmp(server, "all-servers")) {
	    server_rec *s = r->server;

	    while (s) {
	      if (!open_iprot_dbs(r, s->server_hostname,
				  &block_ignore_db, &iprot_db))
		return FALSE;
	      add_block_ignore(r, block_ignore_db, iprot_db,
			       target, s->server_hostname,
			       block_ignore, atoi(days), atoi(hours));
	      close_iprot_dbs(r, &block_ignore_db, &iprot_db);
	      s = s->next;
	    }
	  } else {
	    if (!open_iprot_dbs(r, server,
				&block_ignore_db, &iprot_db))
	      return FALSE;
	    add_block_ignore(r, block_ignore_db, iprot_db,
			     target, server,
			     block_ignore, atoi(days), atoi(hours));
	    close_iprot_dbs(r, &block_ignore_db, &iprot_db);
	  }
	} else {
	  if (!open_iprot_dbs(r, server_hostname,
			      &block_ignore_db, &iprot_db))
	    return FALSE;
	  add_block_ignore(r, block_ignore_db, iprot_db,
			   target, server_hostname,
			   block_ignore, atoi(days), atoi(hours));
	  close_iprot_dbs(r, &block_ignore_db, &iprot_db);
	}
      } /* if */
    } /* for */
  } /* if */

  return OK;
} /* process_block_ignore_form */

static int block_ignore_form(request_rec *r)
{
  server_rec *s = r->server;
  const char *server_hostname = ap_get_server_name(r);
  int all_hosts = -1;

  DBM *block_ignore_db;
  datum db_key, db_nextkey, db_data;

  db_filename_list_ptr fn_list = NULL;
  int table_hdr_printed = FALSE;
  time_t timestamp;
  int i;

  ap_rputs("<form method=\"post\" action=\"iprot-admin?p=block-ignore\">\n",
	   r);
  ap_rprintf(r, "<input type=\"hidden\" name=\"del_type\" value=\"%i\">\n",
	     BLOCK_IGNORE_DELETE);
  ap_rputs("<table border=" TABLE_BORDER " align=center>\n", r);

  while (s) {
    prot_config_rec *prot_conf_rec =	/* module config rec */
      (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

    if (all_hosts == -1)
      all_hosts = prot_conf_rec->all_hosts_admin;

    if (!check_bi_db_filename(prot_conf_rec->block_ignore_filename, fn_list)) {
      /* we haven't done this file yet */
      if (!(block_ignore_db = open_db(prot_conf_rec->block_ignore_filename,
				    IPROT_DB_FLAGS, 0664, r)))
	return FALSE;

      if (!add_db_filenames(prot_conf_rec->filename,
			    prot_conf_rec->block_ignore_filename,
			    &fn_list, r)) {
	ap_rputs("<p align=center><font size=+1>"
		 "Error out of memory.</font></p>\n", r);
	dbm_close(block_ignore_db);
	return OK;
      }

      db_key = dbm_firstkey(block_ignore_db);

      while (db_key.dptr) {
	char *key = NULL, *data = NULL;
	char *target = NULL, *local_host = NULL;

	db_data = dbm_fetch(block_ignore_db, db_key);
	/* check for errors ??? */

	if (!new_str_from_datum(&db_key, &key, r) ||
	    !new_str_from_datum(&db_data, &data, r))  /* out of memory */
	  return FALSE;
	  
	get_items(key, &target, &local_host);
	if (!target || !local_host) {
	  ap_log_rerror(APLOG_MARK, APLOG_CRIT, r,
			"oops! block_ignore_form()");
	  ap_rprintf(r, "</table><br>\n<p align=center><font size=+1>oops!"
		     " block_ignore_form()</font></p></body>\n</html>\n");
	  dbm_close(block_ignore_db);
	  return FALSE;
	}

	if (all_hosts ||
	    !strcmp(local_host, server_hostname)) {
	  timestamp = atoi(strchr(data, ':') + 1);
	  if (timestamp && (timestamp <= r->request_time)) {
	    /* delete expired block or ignore from block_ignore_db and db */
	    DBM *iprot_db;

	    if (!(iprot_db = open_db(prot_conf_rec->filename,
				     IPROT_DB_FLAGS, 0664, r))) {
	      dbm_close(block_ignore_db);
	      return FALSE;
	    }

	    delete_block_ignore(r, block_ignore_db, iprot_db,
				local_host, target, BLOCK_IGNORE_DELETE);
	    dbm_close(iprot_db);
	  } else {
	    if (!table_hdr_printed)	{
	      ap_rputs("<tr><th colspan=6><font size=+1>User Added "
		       "Blocks and Ignores", r);
	      if (all_hosts)
		ap_rprintf(r, " for %s", server_hostname);
	      ap_rputs("</font></th></tr>\n", r);

	      ap_rputs("<tr>\n", r);
	      ap_rputs("<td align=center><b>User Name or "
		       "IP Address</b></td>\n", r);
	      ap_rputs("<td align=center><b>Server Name</b></td>\n", r);
	      ap_rputs("<td align=center><b>Action</b></td>\n", r);
	      ap_rputs("<td align=center colspan=2><b>Expires</b></td>"
		       "<td align=center><b>Delete</b></td>\n", r);
	      ap_rputs("</tr>\n", r);
	      table_hdr_printed = TRUE;
	    }

	    ap_rputs("<tr>\n", r);
	    ap_rprintf(r, "<td>%s</td>\n", target);
	    ap_rprintf(r, "<td>%s</td>\n", local_host);

	    if (data[0] == 'I')
	      ap_rprintf(r, "<td>ignored</td>\n");
	    if (data[0] == 'B')
	      ap_rprintf(r, "<td>blocked</td>\n");

	    /* ap_rprintf(r, "<td>timestamp %li</td>\n", timestamp); */
	    if (timestamp == 0)
	      ap_rputs("<td colspan=2>permanent</td>\n", r);
	    else
	      ap_rprintf(r, "<td colspan=2>%s</td>\n",
			 asc_time(timestamp));
	    /*asc_interval(timestamp - r->request_time));*/

	    ap_rprintf(r, "<td><input type=checkbox name=\"%s?%s\""
		       " value=delete></td>\n", key, local_host);
	    ap_rputs("</tr>\n", r);
	  } /* not expired */
	} /* if (!strcmp(local_host, server_hostname)) */

	db_nextkey = dbm_nextkey(block_ignore_db);
	db_key = db_nextkey;
      } /* while */

      dbm_close(block_ignore_db);
    } /* if not a duplicate filename */

    s = s->next;
  } /* while <virtual server>*/

  if (!table_hdr_printed) {
    ap_rprintf(r, "<tr><th colspan=6><b><font size=+1>"
	       "No User Added Blocks or Ignores");
    if (!all_hosts)
      ap_rprintf(r, " for %s</font></b></th></tr>\n", server_hostname);
  }

  ap_rprintf(r, "<tr><td colspan=6></td></tr>"
	     "<tr><td colspan=6></td></tr>"
	     "<tr><td colspan=6></td></tr>"
	     "<tr><th colspan=6><font size=+1>Add Blocks and Ignores for ");

  if (all_hosts)
    ap_rprintf(r, "<u>Any</u> Server</font></th></tr>\n");
  else
    ap_rprintf(r, "%s</font></th></tr>\n", server_hostname);

  ap_rputs("<tr>\n"
	   "<td align=center><b>User Name or IP Address</b></td>\n"
	   "<td align=center><b>Server Name</b></td>\n"
	   "<td align=center><b>Block</b></td>\n"
	   "<td align=center><b>Ignore</b></td>\n"
	   "<td align=center><b>Days</b></td>\n"
	   "<td align=center><b>Hours</b></td>\n</tr>\n", r);

  for (i = 0; i < N_NEW_BLOCKS; i++) {
    ap_rprintf(r, "<tr>\n");
    ap_rprintf(r, "  <td><input type=text name=target_%i "
	       "size=" TARGET_NAME_LENGTH
	       " maxlength=" TARGET_NAME_LENGTH "></td>\n", i);
    ap_rprintf(r, "<td>\n");
    if (all_hosts) {
      if (i == N_NEW_BLOCKS - 1)
	ap_rprintf(r, "<input type=text name=server_%i size=24"
		   " maxlength=60 value=%s>\n",
		   i, server_hostname);
      else
	virt_server_menu(r, i);
    } else {
      ap_rprintf(r, "<input type=hidden name=server_%i value=%s>\n",
		 i, server_hostname);
      ap_rprintf(r, server_hostname);
    }
    ap_rprintf(r, "</td>\n");
    ap_rprintf(r, "<td align=center>\n<input type=radio "
	       "name=block_ignore_%i value=B checked>\n</td>\n", i);
    ap_rprintf(r, "<td align=center>\n<input type=radio "
	       "name=block_ignore_%i value=I>\n</td>\n", i);
    ap_rprintf(r, "<td align=center><input type=text name=days_%i size=3 "
	       "maxlength=3 value=0></td>\n", i);
    ap_rprintf(r, "<td align=center><input type=text name=hours_%i size=3 "
	       "maxlength=3 value=0></td>\n", i);
    ap_rputs("<td></td><td></td></tr>\n", r);
  } /* for */

  ap_rputs("<tr><td>\n<input type=submit value=\"Submit\">"
	   "<input type=reset value=\"Clear\"></td>\n"
	   "<td colspan=5 align=right>\n<font size=-1>Set <b>Days</b> "
	   "and <b>Hours</b> to <b>0</b> for <u>permanent</u> <b>Block</b> or "
	   "<b>Ignore</b>.</font></td></tr>\n</table>\n </form>\n", r);
  return OK;
} /* block_ignore_form */

int iprot_block_ignore(request_rec *r) /* p=block-ignore */
{
  server_rec *s = r->server;
  const char *server_hostname = ap_get_server_name(r);
  prot_config_rec *prot_conf_rec =	/* module config rec */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);
  table *post_params_table = NULL;
  int rc;

  r->no_cache = 1;
  r->content_type = "text/html";
  ap_send_http_header(r);
 
  ap_rputs("<html><header>\n<title>iProtect User Added Blocks and Ignores "
	   "</title>\n</header><body>\n", r);
  ap_rputs("<p align=center><font size=+3>"
	   "iProtect User Added Blocks and Ignores </font>\n"
	   "<br>" COPYRIGHT_NOTICE "\n"
	   "<br><a href=\"" SUPPORT_MAIL_URL "\">Email Support</a></p>\n", r);
  ap_rputs("<p align=center><a href=\"iprot-admin\">"
	   "iProtect Admin Menu</a><br>\n", r);

  if (!prot_conf_rec->all_hosts_admin)
    ap_rprintf(r, "<br><font size=+1>Server: %s</font>\n", server_hostname);

  ap_rputs("</p><table border=" TABLE_BORDER " align=center>\n", r);
  ap_rprintf(r, "<tr><td><b>Current Time</b></td>"
	     "<td>%s</td></tr>\n", asc_time(r->request_time));
  ap_rputs("</table><br>\n", r);

  if ((rc = read_post_params(r, &post_params_table)) != OK) {
    ap_rprintf(r, "<p align=center><font size=+1>"
	       "Error %i getting post parameters.</font><p>\n", rc);
    ap_rputs("</body></html>\n", r);
    return rc;
  }

  if (post_params_table && !ap_is_empty_table(post_params_table)) {
    enum del_types del_type =
      atoi(ap_table_get(post_params_table, "del_type"));

    if (del_type == BLOCK_IGNORE_DELETE)
      process_block_ignore_form(r, post_params_table);
  }

  block_ignore_form(r);

  ap_rputs("<p align=center><a href=\"iprot-admin\">"
	   "iProtect Admin Menu</a></p>\n</body></html>\n", r);
  return OK;
} /* iprot_block_ignore */

int iprot_admin(request_rec *r)
{
  const char *server_hostname = ap_get_server_name(r);
  char *page;

  if (r->args) {
    if (get_get_param(r, "p", &page)) {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, r, "iprot_admin p=%s", page);

      if (!strcmp(page, "view-edit"))
	return iprot_view_edit_blocks(r);
      else
	if (!strcmp(page, "block-ignore"))
	  return iprot_block_ignore(r);
	else
	  if (!strcmp(page, "config"))
	    return iprot_configuration(r);
	  else
	    if (!strcmp(page, "block-detail"))
	      return iprot_block_detail(r);
	    else
	      if (!strcmp(page, "user-detail-display"))
		return iprot_db_display(r, TRUE);
#if DISPLAY_DB
	      else
		if (!strcmp(page, "db-display"))
		  return iprot_db_display(r, FALSE);
#endif

      ap_rputs("<html><head></head><body>"
	       "<p><b>iProtect: Unknown page requested in iprot_admin()."
	       "</b></p></body></html>\n", r);
      return OK;
    }
  }

  r->content_type = "text/html";
  ap_send_http_header(r);
 
  ap_rputs("<html><header>\n<title>iProtect Admin "
	     "(version " IPROT_VERSION ")</title>\n</header><body>\n", r);

  ap_rputs("<p align=center><font size=+3>"
	   "iProtect Admin</font>\n", r);
  ap_rputs("<br>" COPYRIGHT_NOTICE "\n", r);
  ap_rputs("<br><a href=\"" SUPPORT_MAIL_URL "\">Email Support</a>\n", r);
  ap_rprintf(r, "<br><font size=+1>Server: %s</font></p>\n", server_hostname);

  ap_rputs("<table border=" TABLE_BORDER " align=center>\n", r);
  ap_rputs("<tr><td><a href=\"iprot-admin?p=view-edit\">"
	   "View/Edit iProtect Blocks</a></td></tr>\n", r);
  ap_rputs("<tr><td><a href=\"iprot-admin?p=block-ignore\">"
	   "User Added Blocks and Ignores</a></td></tr>\n", r);
  ap_rputs("<tr><td><a href=\"iprot-admin?p=config\">"
	   "iProtect Configuration</a></td></tr>\n", r);
  ap_rputs("<tr><td><a href=\"iprot-admin?p=user-detail-display\">"
	   "User Details</a></td></tr>\n", r);
#if DISPLAY_DB
  ap_rputs("<tr><td><a href=\"iprot-admin?p=db-display\">"
	   "Display Database</a></td></tr>\n", r);
#endif
  ap_rputs("</ul>\n", r);

  ap_rputs("</body></html>\n", r);

  return OK;
} /* iprot_admin */
