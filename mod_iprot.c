/*
 * iProtect for Apache
 *
 * Copyright 1999-2003, Digital Concepts
 *
 * http://www.digital-concepts.net
 */

#include "mod_iprot.h"
#include "http_request.h"
#include <errno.h>

/* Log a fatal error and abort during server initialization. */
static void server_init_abort(server_rec *s)
{
  ap_log_error(APLOG_MARK, APLOG_CRIT, s, strerror(errno));
  exit(errno);
}

#if 0
static void mod_init(server_rec *s, pool *p) {
  prot_config_rec *rec =	/* get our module configuration record */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);
  if (!rec) server_init_abort(s);

  if (rec->email != NULL) {
    rec->abuse_email =
      rec->abuse_email ? rec->abuse_email : rec->email;
    rec->hack_email =
      rec->hack_email ? rec->hack_email : rec->email;
    rec->bw_email =
      rec->bw_email ? rec->bw_email : rec->email;
  }
}
#endif

/* function to initialize server config structure */
static void *create_prot_config(pool *p, server_rec *s)
{
  prot_config_rec *rec =
    (prot_config_rec *) PALLOC (p, sizeof(prot_config_rec));
  if (!rec) server_init_abort(s);

  ap_log_error(APLOG_MARK, APLOG_INFO, s, "initializing mod_iprot");

  if (!(rec->threshold = (char *) PSTRDUP(p, IPROT_THRESHOLD))) /* num hits */
    server_init_abort(s);
  if (!(rec->auth_timeout = (char *) PSTRDUP(p, IPROT_AUTH_TIMEOUT)))
    server_init_abort(s);	    /* timeout for authorizations */
  if (!(rec->access_timeout = (char *) PSTRDUP(p, IPROT_ACCESS_TIMEOUT)))
    server_init_abort(s);	    /* timeout for accesses */
  if (!(rec->filename = (char *) PSTRDUP(p, IPROT_DB_FILE)))
    server_init_abort(s);
  /*
  if (!(rec-> = (char *) PSTRDUP(p, )))
    server_init_abort(s);
  */
  if (!(rec->compareN = (char *) PSTRDUP(p, IPROT_COMPARE_N)))
    server_init_abort(s);

  rec->external_progip = NULL;
  rec->external_proguser = NULL;

  rec->email = NULL;
  rec->abuse_email = NULL;
  rec->hack_email = NULL;
  rec->bw_email = NULL;

  if (!(rec->failed_threshold = (char *) PSTRDUP(p, IPROT_FAILED_THRESHOLD)))
    server_init_abort(s);	/* threshold number of ips for
				 * failed login for one user */
  if (!(rec->failed_timeout = (char *) PSTRDUP(p, IPROT_FAILED_TIMEOUT)))
    server_init_abort(s);	 /* timeout for failed logins */
  if (!(rec->failed_compareN = (char *) PSTRDUP(p, IPROT_FAILED_COMPARE_N)))
    server_init_abort(s);
  if (!(rec->block_ignore_filename =
	(char *) PSTRDUP(p, IPROT_BLOCKIGNORE_DB_FILE)))
    server_init_abort(s);

  rec->abuse_status_return = 1; /* return HTTP STATUS Forbidden (403) */
  rec->hack_status_return = 1;	/* status by default */
  rec->abuse_redirect_url = NULL;
  rec->hack_redirect_url = NULL;

  rec->bw_status_return = 1;	/* return HTTP STATUS Forbidden (403) 
				 * status by default */
  if (!(rec->max_bytes_user = (char *) PSTRDUP(p, IPROT_MAX_BYTES_USER)))
    server_init_abort(s);	/* default is disabled */
  rec->bw_timeout = 0;

  rec->bw_redirect_url = NULL;

  rec->nag = 0;
  rec->notifyip = 1;	  	/* send hack attempt mail by default */
  rec->notifyuser = 1;	  	/* send abuse mail by default */
  rec->notifylogin = 1;	  	/* send failed login mail by default */
  rec->notifybw = 1;	  	/* send bw block mail by default */

  rec->enabled = 1;	  	/* enabled by default */
  rec->no_HEAD_req = 0;	  	/* process HEAD requests by default */
  rec->all_hosts_admin = 0;	/* show all hosts in admin off by default */

  if (!(rec->ipaddress_preg =
	ap_pregcomp(p, "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+",
		    REG_EXTENDED | REG_NOSUB)) ||
      !(rec->ignore_ips = ap_make_table(p, 20)) ||
	!(rec->ignore_users = ap_make_table(p, 20)))
    server_init_abort(s);

  return (void *)rec;
} /* create_prot_config */

/* function to initialize virtual server config structure */
static void *merge_prot_config(pool *p, void *basev, void *newv)
{
  prot_config_rec *base, *new;
  array_header *arr;

  base = (prot_config_rec *)basev;
  new = (prot_config_rec *)newv;
  
  new->threshold =
    strcmp(new->threshold, IPROT_THRESHOLD) ?
    new->threshold : base->threshold;
  new->auth_timeout =
    new->auth_timeout != NULL ? new->auth_timeout : base->auth_timeout;
  new->auth_timeout =
    strcmp(new->auth_timeout, IPROT_AUTH_TIMEOUT) ?
    new->auth_timeout : base->auth_timeout;
  new->access_timeout =
    strcmp(new->access_timeout, IPROT_ACCESS_TIMEOUT) ?
    new->access_timeout : base->access_timeout;
  new->filename =
    strcmp(new->filename, IPROT_DB_FILE) ?
    new->filename : base->filename;
    /*
  new-> =
    strcmp(new->, ) ?
    new-> : base->;
    */
  new->compareN =
    strcmp(new->compareN, IPROT_COMPARE_N) ?
    new->compareN : base->compareN;

  new->email =
    new->email != NULL ? new->email : base->email;
  new->abuse_email =
    new->abuse_email != NULL ? new->abuse_email : base->abuse_email;
  new->hack_email =
    new->hack_email != NULL ? new->hack_email : base->hack_email;
  new->bw_email =
    new->bw_email != NULL ? new->bw_email : base->bw_email;

  if (new->email != NULL) {
    new->abuse_email =
      new->abuse_email ? new->abuse_email : new->email;
    new->hack_email =
      new->hack_email ? new->hack_email : new->email;
    new->bw_email =
      new->bw_email ? new->bw_email : new->email;
  }

  new->external_progip =
    new->external_progip != NULL ? new->external_progip :
  new->external_proguser =
    new->external_proguser != NULL ? new->external_proguser :
				     base->external_proguser;
  new->failed_threshold =
    strcmp(new->failed_threshold, IPROT_FAILED_THRESHOLD) ?
    new->failed_threshold : base->failed_threshold;
  new->failed_timeout =
    strcmp(new->failed_timeout, IPROT_FAILED_TIMEOUT) ?
    new->failed_timeout : base->failed_timeout;
  new->failed_compareN =
    strcmp(new->failed_compareN, IPROT_FAILED_COMPARE_N) ?
    new->failed_compareN : base->failed_compareN;

  new->abuse_status_return = new->abuse_status_return;
  new->abuse_redirect_url =
    new->abuse_redirect_url != NULL ?
    new->abuse_redirect_url : base->abuse_redirect_url;

  new->hack_status_return = new->hack_status_return;
  new->hack_redirect_url =
    new->hack_redirect_url != NULL ?
    new->hack_redirect_url : base->hack_redirect_url;

  new->bw_status_return = new->bw_status_return;

  new->max_bytes_user =
    strcmp(new->max_bytes_user, IPROT_MAX_BYTES_USER) ?
    new->max_bytes_user : base->max_bytes_user;

  new->bw_redirect_url =
    new->bw_redirect_url != NULL ?
    new->bw_redirect_url : base->bw_redirect_url;

  new->bw_timeout = (new->bw_timeout) ? new->bw_timeout : base->bw_timeout;

  new->block_ignore_filename =
    strcmp(new->block_ignore_filename, IPROT_BLOCKIGNORE_DB_FILE) ?
    new->block_ignore_filename : base->block_ignore_filename;

  new->nag = new->nag ? new->nag : base->nag;
  new->enabled = new->enabled ? new->enabled : base->enabled;
  new->notifyip = new->notifyip ? new->notifyip : base->notifyip;
  new->notifyuser = new->notifyuser ? new->notifyuser : base->notifyuser;
  new->notifylogin = new->notifylogin ? new->notifylogin : base->notifylogin;
  new->notifybw = new->notifybw ? new->notifybw : base->notifybw;
  new->no_HEAD_req = new->no_HEAD_req ? new->no_HEAD_req : base->no_HEAD_req;
  new->all_hosts_admin = FALSE;

  new->ipaddress_preg = base->ipaddress_preg;

  arr = ap_table_elts(new->ignore_ips);
  if (!arr->nelts)
    new->ignore_ips = base->ignore_ips;

  arr = ap_table_elts(new->ignore_users);
  if (!arr->nelts)
    new->ignore_users = base->ignore_users;

  return (void *)new;
} /* merge_prot_config */

static void send_mail(request_rec *r,
		      const char *ip, const char *target,
		      const char *email, const char *host,
		      const char *subject, const char *message,
		      const char *expires_1, const char *expires_2)
{
  server_rec *s = r->server;
# define BUFFER_LEN 256
  char buffer[BUFFER_LEN];
  FILE *pi;
  const time_t timestamp = r->request_time;
		      
  ap_log_error(APLOG_MARK, APLOG_INFO, s,
	       "mod_iprot: sending email to %s", email);
  /* Open email command. Must be in default shell's path. */
  snprintf(buffer, BUFFER_LEN, "sendmail -t");
  pi = popen(buffer, "w");
  if (pi == NULL) {
    ap_log_reason("Can't execute command.", "sendmail", r);
    return;
  }

  /* mail header: */
  fprintf(pi, "To: %s\n", email);
  fprintf(pi, "Subject: %s [%s]\n", subject, target);
  /* end of headers */
  fprintf(pi, "\n");

  /* Dump message: */
  fprintf(pi, "%s, denying further access.\n\n", message);
  fprintf(pi, "target: %s\n", target);
  fprintf(pi, "timestamp: %s", ctime(&timestamp));
  fprintf(pi, "browser ip: %s\n", ip);
  fprintf(pi, "server hostname: %s\n", host); 
  fprintf(pi, "expires in: %s %s.\n", expires_1, expires_2);

  pclose(pi);
} /* send_mail */

static void call_external(request_rec *r, const char *ip, const char *cmd)
{
# define BUFFER_LEN 256
  char buffer[BUFFER_LEN];
  FILE *pi;
  
  /* Open external cmd. Must be in shell path, or full path specified. */
  snprintf(buffer, BUFFER_LEN, (const char *)cmd, (const char*) ip);
  pi = popen(buffer, "w");
  if (pi == NULL) {
    ap_log_reason("Can't execute command.", cmd, r);
    return;
  }

  pclose(pi);
} /* call_external */

/* return true if user string found in any table entry,
   where each table entry is a string used for a regex */
static int match_string(request_rec *r, table *t, char *str)
{
  regex_t *regex;
  int i, match;
  array_header *arr;
  table_entry *elts;

  if (!t || !str)
    return FALSE; /* no match by definition */

  arr = ap_table_elts(t);
  elts = (table_entry *) arr->elts;

  for (i = 0; i < arr->nelts; ++i) {
    regex = ap_pregcomp(r->pool, elts[i].key, REG_EXTENDED | REG_NOSUB);
    match = ap_regexec(regex, str, 0, NULL, 0);
    ap_pregfree(r->pool, regex);
    if (match == 0) return TRUE;
  }
  return FALSE;
} /* match_string */

/* get an HTTP header. Use this for HTTP_X_FORWARDED  */
static char *lookup_header(request_rec *r, const char *name)
{
  array_header *hdrs_arr;
  table_entry *hdrs;
  int i;

  hdrs_arr = ap_table_elts(r->headers_in);
  hdrs = (table_entry *) hdrs_arr->elts;
  for (i = 0; i < hdrs_arr->nelts; ++i) {
    if (hdrs[i].key == NULL)
      continue;
    if (strcasecmp(hdrs[i].key, name) == 0)
      return hdrs[i].val;
  }
  return NULL;
} /* lookup_header */

/* Update the timestamp of item in footprintStr and return a new
 * footprintStr. */
static char *update_timestamp(request_rec *r,
			      char *footprintStr,
			      const char *item,
			      const time_t new_timestamp)
{
# undef BUFFER_LEN
# define BUFFER_LEN 32
  char *p1, *p2, *p3;
  char *oldfootprint = (char *) PSTRDUP (r->pool, footprintStr);
  char *newfootprint = (char *) PALLOC (r->pool, strlen(footprintStr) + 2);
  char *new_timestamp_str = (char *) PALLOC (r->pool, BUFFER_LEN);
  /* new_timestamp_str[BUFFER_LEN] causes an error. */

  if (!footprintStr || !item) return NULL;

  if (!oldfootprint || !newfootprint || !new_timestamp_str) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return NULL;
  }

  snprintf(new_timestamp_str, BUFFER_LEN, "%lu", new_timestamp);
  p1 = strstr(oldfootprint, item);

  if (p1) {
    p2 = strchr(p1, ':');
    p3 = strchr(p2, ';');
    p2++;
    p2[0] = (char) NULL;
    strncpy(newfootprint, oldfootprint, strlen(footprintStr));
    strncat(newfootprint, new_timestamp_str,
	    strlen(footprintStr) - strlen(newfootprint));
    if (p3)
      strncat(newfootprint, p3,
	      strlen(footprintStr) - strlen(newfootprint));
    return newfootprint;
  } else {
    return footprintStr; /* item not found */
  }
} /* update_timestamp */

int count_hits(request_rec *r, const char *key, const char *item,
	       char *footprintStr, char **newFootprint,
	       const int interval, const int compareN,
	       const int threshold, const char add_item,
	       const prot_config_rec *config_rec)
{
  footprint *footprint_list;
  char *ques_ptr;
  int i, j, chars_to_count, item_match, num_items;
  server_rec *s = r->server;
  char buffer[128];
  char ques_char = '?';
  int footprintStr_len = strlen(footprintStr); /* get length here, */
		      /* get_footprint_list() changes footprintStr */
  time_t exp;

  if (index(footprintStr, '\xbf') != NULL) ques_char = '\xbf'; /* '¿' */
  /* Preseve the ques_char even if list pruned to 0. */
  
  num_items = atoi(footprintStr);  /* Get number in footprint list
				    * before we work on it. */
  footprint_list = /* Allocate enough space for one new record. */
    PALLOC(r->pool, sizeof(footprint) * (num_items + 1));
  if (!footprint_list) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return -1;
  }

  /* This will prune the list of expired entries. */
  num_items = get_footprint_list(footprintStr, footprint_list,
				 (long) r->request_time, &exp);

  /* If we're over the threshold after prune, don't bother continuing. */
  if (num_items > threshold) {
    ap_log_error(APLOG_MARK, APLOG_INFO, s,
		 "mod_iprot: count %d exceeds threshold %d, "
		 "blocking immediately.",
		 num_items, threshold);
    *newFootprint = NULL;
    return num_items;	 /* bad user */
  }

  if (!(*newFootprint = /* Space for 1 new item. */
	(char *) PALLOC(r->pool, 20 + strlen(item) + footprintStr_len))) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return -1;
  }

  /* start a new footprintStr for building as we go */
  sprintf(*newFootprint, "%d%c",
	  (add_item ? num_items + 1 : num_items), ques_char);
  
  for (i = 0; i < num_items; i++) {
    item_match = 1;
    chars_to_count = 0;

    /* First check if this item is a name or an IP. */
    if (isipaddress(config_rec, item)) {
      /* Compare the first compareN octets of an IP. */
      for (j = 0; j < compareN; j++)
	chars_to_count =
	  chars_to_count + 1 + strcspn(item + chars_to_count, ".");

      item_match = strncmp(footprint_list[i].item, item, chars_to_count);
    } else {
      /* It's a name, compare the whole thing. */
      item_match = strcmp(footprint_list[i].item, item);
    }
	
    /* If this item exists, abort further processing and return OK.
     * This causes the items that caused the block to be exempt from
     * the block because we return 0. */
    if (!item_match) {
      LOG_PRINTF(s, "mod_iprot: item %s found in list, returning OK", item);
      *newFootprint = NULL; /* Don't change. Update timestamp?? */
      return 0; /* ok user */
    } else {
      /* else put this IP back on the string */
      sprintf(buffer, "%s:%li;",
	      footprint_list[i].item,
	      footprint_list[i].timestamp); /* Don't update timestamp. */
      strcat(*newFootprint, buffer);
    }
  }
  
  /* update num_items to reflect an added item */
  num_items = atoi(*newFootprint);

  /* email will be sent for this access, set the no-nag flag */
  if (num_items == threshold) {
    ques_ptr = strchr(*newFootprint, '?');
    if (ques_ptr != NULL)
      *ques_ptr = '\xbf';  /* ¿ */
  }

  if (add_item) {
    /* if we got this far, then the ip address is new or was removed as
       expired by get_footprint_list(), so add it to the list */
    sprintf(buffer, "%s:%li", item, (long) (r->request_time + interval));
    strcat(*newFootprint, buffer);

    LOG_PRINTF(s, "mod_iprot: item %s was not found on list", item);
    LOG_PRINTF(s, "mod_iprot: new record value = %s", *newFootprint);
  } else {
    if (*newFootprint && strlen(*newFootprint) < 10)
      strcpy(*newFootprint, ""); /* not NULL because it's been changed */
  }

  return num_items;
} /* count_hits */

static int check_failed_auth_attempts(request_rec *r,
				      conn_rec *c,
				      server_rec *s,
				      prot_config_rec *config_rec,
				      const char *remote_ip,
				      const char *admin_email/*,
				      const char *abuse_email,
				      const char *hack_email???*/)
{
  DBM *db;
  datum d;
  char *newFootprint = NULL;
  char *successfulIPStr = "";
  char *failedIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";
  int count, nag;
  const long interval = atol(config_rec->failed_timeout);
  const int compareN = atoi(config_rec->failed_compareN);
  const int failed_threshold = atoi(config_rec->failed_threshold);
  const char *server_name = ap_get_server_name(r);
  int status;

  if (!(db = open_iprot_db(config_rec->filename, IPROT_DB_FLAGS, 0664, r)))
    return -1; /* I/O Error */

  if (!(get_record(db, &d, server_name, c->user, r)) ||
      !(get_data_strings(r, &d,
			 &successfulIPStr, &failedIPStr,
			 &BlockIgnoreStr, &BWStr))) {
    close_db(&db, r); 
    return -1; /* I/O Error */
  }

  /* Check for block or ignore on user. */
  if (strcmp(BlockIgnoreStr, "")) {
    int block_status;

    if ((block_status = check_block_ignore(BlockIgnoreStr, db,
					   server_name, c->user,
					   config_rec, r))) {
      close_db(&db, r); 
      return block_status; /* blocked, ignored or error */
    }
  }

  if (strcmp(failedIPStr, "")) {
    /* if db record indicates no mail has yet been sent for this entry,
       then send something. otherwise, obey the config file */
    if (index(failedIPStr, '\xbf') == NULL)  /* ¿ */
      nag = 1;
    else 
      nag = config_rec->nag;

    if ((count = count_hits(r, c->user, remote_ip,
			    failedIPStr, &newFootprint,
			    interval, compareN, failed_threshold, 0,
			    config_rec)) == -1)	{
      close_db(&db, r); 
      return -1; /* error in count_hits() */
    }

    if (newFootprint) { /* changed in count_hits() */
      char *IPdata = NULL;

      if (!(IPdata = combine_data_strings(r,
					  successfulIPStr,
					  newFootprint,
					  BlockIgnoreStr,
					  BWStr))) {
	/* out of memory */
	close_db(&db, r); 
	return -1;
      }

      store_record(db, server_name, c->user, IPdata, r);
    }

    if (count >= failed_threshold) {
      char *cmp_ip;

      /* check for recent successful logins from this ip */
      if (!(cmp_ip = (char *) PALLOC(r->pool, strlen(remote_ip) + 1))) {
	/* out of memory */
	ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
	close_db(&db, r); 
	return -1;
      }
      strcpy(cmp_ip, "");

      if (compareN < 4) {
	char *tmp_ip, *oct;
	int i;

	tmp_ip = (char *) PALLOC(r->pool, strlen(remote_ip) + 1);
	if (!tmp_ip) {
	  /* out of memory */
	  ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
	  close_db(&db, r); 
	  return -1;
	}
	strcpy(tmp_ip, remote_ip);

	oct = strtok(tmp_ip, ".");
	for (i = 0; i < compareN; i++) {
	  strcat(cmp_ip, oct);
	  strcat(cmp_ip, ".");
	  oct = strtok(NULL, ".");
	}
      } else {
	strcpy(cmp_ip, remote_ip);
      }

      if (strcmp(successfulIPStr, "") && strstr(successfulIPStr, cmp_ip)) {
	status = 0;
      } else {
	/* username is being abused, block */
	ap_log_error(APLOG_MARK, APLOG_INFO, s,
		     "mod_iprot: failed login threshold "
		     "exceeded for: %s at server %s",
		     c->user, server_name); 

	if (config_rec->external_progip != NULL) {
	  ap_log_error(APLOG_MARK, APLOG_INFO, s,
		       "mod_iprot: calling external program %s",
		       config_rec->external_progip);
	  call_external(r, remote_ip,
			config_rec->external_progip);
	}

	status = (count > failed_threshold) ? 1 : 0;
      }
    } else {
      status = 0;
    }
  } else {
    status = 0; /* no record of this ip */
  }

  close_db(&db, r);
  return status;
} /* check_failed_auth_attempts */ 

static int check_bandwidth(request_rec *r)
{
  server_rec *s = r->server;
  conn_rec *c = r->connection;
  const char *server_hostname = ap_get_server_name(r);

  char *successfulIPStr = "";
  char *failedIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";

  DBM *db;
  datum d;

  int rtn = 0; /* return value -1: error, 0: not blocked, 1: blocked */
  time_t timestamp = 0;
  int max_bytes_user;
  int total_bytes_sent;
  char flag_char;

  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* open database */
  if (!(db = open_iprot_db(config_rec->filename, IPROT_DB_FLAGS, 0664, r)))
    return -1; /* I/O Error */

  /* get user's data record and bw str */
  if (!(get_record(db, &d, server_hostname, c->user, r)) ||
      !(get_data_strings(r, &d,
			 &successfulIPStr, &failedIPStr,
			 &BlockIgnoreStr, &BWStr))) {
    close_db(&db, r); 
    return -1; /* I/O Error or out of memory*/
  }

  if (strcmp(BWStr, "")) {
    if (sscanf(BWStr, "%i%c%i", &total_bytes_sent,
	       &flag_char, (int *)&timestamp) == 3) {
      if (config_rec->bw_timeout &&  /* periodic block? */
	  diff_day(timestamp, r->request_time)) {  /* new calendar day? */
	char *dataStr = NULL;
	/* store user's record with zeroed bw data, record_bytes_sent
	   will create a new record with a new date */
	if ((dataStr =
	     combine_data_strings(r, successfulIPStr, failedIPStr,
				  BlockIgnoreStr, ""))) {
	  store_record(db, server_hostname, c->user, dataStr, r);
	}
      } else {
	max_bytes_user = atoi(config_rec->max_bytes_user);

	if (total_bytes_sent > (max_bytes_user * MBYTE)) {
	  /* user has exceeded maximum transfer */

	  if (config_rec->bw_timeout &&  /* periodic block? */
	      ((timestamp + (config_rec->bw_timeout * SEC_PER_HOUR)) <
	       r->request_time)) {
	    /* block has expired, remove */
	    char *dataStr = NULL;
	    if ((dataStr =
		 combine_data_strings(r, successfulIPStr, failedIPStr,
				      BlockIgnoreStr, ""))) {
	      store_record(db, server_hostname, c->user, dataStr, r);
	    }
	    return 0;
	  }

	  rtn = 1;
	  /* send email ? */
	  if (((flag_char == S_CHAR) || config_rec->nag) &&
	      config_rec->notifybw) {
	    char *admin_email =
	      (config_rec->bw_email == NULL) ?
	      s->server_admin : config_rec->bw_email;

	    /* get the real ip, if possible, otherwise go with c->remote_ip */
	    char *remote_ip = lookup_header(r, "HTTP_X_FORWARDED_FOR");
	    if (remote_ip == NULL) remote_ip = c->remote_ip;

	    if (config_rec->bw_timeout) {
	      char buf[8];

	      snprintf(buf, 8, "%i", config_rec->bw_timeout);
	      send_mail(r, remote_ip, c->user, 
			admin_email, server_hostname,
			"iProtect BandWidth notification",
			"Daily BandWidth exceeded for user",
			buf, "hours");
	    } else {
	      send_mail(r, remote_ip, c->user, 
			admin_email, server_hostname,
			"iProtect BandWidth notification",
			"Daily BandWidth exceeded for user",
			"1", "day");
	    }

	    if (flag_char == S_CHAR) {
#	      undef BUFFER_LEN
#	      define BUFFER_LEN 32
	      char buffer[BUFFER_LEN];
	      char *dataStr = NULL;

	      /* make a new bw str */
	      flag_char = S_CHAR_MAILED;
	      snprintf(buffer, BUFFER_LEN, "%i%c%i", total_bytes_sent,
		       flag_char, (int)timestamp);

	      /* store user's record */
	      if ((dataStr =
		   combine_data_strings(r, successfulIPStr, failedIPStr,
					BlockIgnoreStr, buffer))) {
		store_record(db, server_hostname, c->user, dataStr, r);
	      }
	    }
	  } /* send email */
	}
      }
    } else {
      rtn = -1; /* error scanning string */
    }
  }

  close_db(&db, r);

  return rtn;
} /* check_bandwidth */

/* Basic auth step, watch for multiple login attempts from one IP. */
static int record_auth_attempt(request_rec *r)
{
  server_rec *s = r->server;
  conn_rec *c = r->connection;
  const char *server_hostname = ap_get_server_name(r);

  char *ptr;
  char *PWStr = "";
  char *BlockIgnoreStr = "";
  char *dataStr = NULL;
  const char *sent_pw;
  char *admin_email;
  char *abuse_email;
  char *hack_email;
# undef BUFFFER_LEN
# define BUFFFER_LEN 128
  char buffer[BUFFFER_LEN];
  int compareN, res, num_hits, threshold, nag;
  long interval;
  char *remote_ip;
  char *newFootprint = NULL;

  DBM *db;
  datum d;

  prot_config_rec *rec =	/* module config rec */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* if basic auth hasn't triggered yet, prompt for password */
  if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
    return res;

  /* defensive programming */
  if (strlen(sent_pw) == 0) return DECLINED;
  if (strlen(c->user) == 0) return DECLINED;

  /* strip ; and : from the passwd, because we use them as separators */
  /* just replace with a space for now */
  while ((ptr = strchr(sent_pw, ';')) != NULL)
    *ptr = ' '; 
  while ((ptr = strchr(sent_pw, ':')) != NULL)
    *ptr = ' '; 
  
  /* get the real ip, if possible, otherwise go with c->remote_ip */
  remote_ip = lookup_header(r, "HTTP_X_FORWARDED_FOR");
  if (remote_ip == NULL) remote_ip = c->remote_ip;

  LOG_PRINTF(s, "mod_iprot: record_auth enabled_flag = %d", rec->enabled);

  if (!rec->enabled)  /* enable flag is not set */
    return DECLINED;

  /* if the user is in the ignore list, just ignore it... */
  if (match_string(r, rec->ignore_users, c->user))
    return DECLINED;

  /* if the ip is in the ignore list, just ignore it... */
  if (match_string(r, rec->ignore_ips, remote_ip))
    return DECLINED;

  if (r->header_only && rec->no_HEAD_req)
    return DONE; /* HEAD request, close connection w/o returning anything. */
		 /* Do this here so we only affect requests for pages */
		 /* requiring authentication. */

  /* allow the IProtEmail to override the server admin, if set. Could
     this be moved to the configuration section???*/
  if (rec->hack_email == NULL)
    admin_email = s->server_admin;
  else
    admin_email = rec->hack_email;

  /* check for number of failed logins from different ips */
  if (rec->failed_timeout && rec->failed_threshold)
    switch (check_failed_auth_attempts(r, c, s, rec, remote_ip, admin_email)) {
    case -1:	/* error or user ignored */
      return DECLINED;
    case 0:	/* no error or abuse, continue processing */
      break;
    case 1:	/* password cracking blocked */
      switch (rec->hack_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (rec->hack_redirect_url)
	  ap_internal_redirect(rec->hack_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    }

  /* check for bandwidth used */
  if (atoi(rec->max_bytes_user))
    switch (check_bandwidth(r)) {
    case -1:	/* error */
      return DECLINED;
    case 0:	/* no error or abuse, continue processing */
      break;
    case 1:	/* password cracking blocked */
      switch (rec->bw_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (rec->bw_redirect_url)
	  ap_internal_redirect(rec->bw_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    }

  /* interval for login attempts is in seconds, not hours */
  if (rec->auth_timeout == NULL || rec->threshold == NULL)
    return DECLINED;

  compareN = atoi(rec->compareN);
  interval = atol (rec->auth_timeout);	
  threshold = atoi (rec->threshold);

  /* open iprot database */
  if (!(db = open_db(rec->filename, IPROT_DB_FLAGS, 0664, r)))
    return DECLINED;

  /* read a password record */
  LOG_PRINTF(s, "mod_iprot: getting record for IP %s", remote_ip);
  if (!get_record(db, &d, server_hostname, remote_ip, r) ||
      !get_data_strings(r, &d, &PWStr, &BlockIgnoreStr, NULL, NULL)) {
    close_db(&db, r); 
    return DECLINED;
  }

  /* Check for block or ignore on IP. */
  if (strcmp(BlockIgnoreStr, ""))
    switch (check_block_ignore(BlockIgnoreStr, db,
			       server_hostname, remote_ip,
			       rec, r)) {
    case -1:	/* error or ip ignored */
      close_db(&db, r); 
      return DECLINED;
    case 0:	/* no error or abuse, continue processing */
      break;
    case 1:	/* password cracking detected or blocked */
      close_db(&db, r);
      switch (rec->hack_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (rec->hack_redirect_url)
	  ap_internal_redirect(rec->hack_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    }

  if (strcmp(PWStr, "")) {
    LOG_PRINTF(s, "mod_iprot: PWStr = %s", PWStr);

    /* If db record indicates no mail has yet been sent for this entry,
       then send something. otherwise, obey the config file. */
    if (index(PWStr, '\xbf') == NULL)	 /* ¿ */
      nag = 1;
    else 
      nag = rec->nag;

    ap_log_error(APLOG_MARK, APLOG_INFO, s,
		 "mod_iprot: nag = %d notifyip = %d",
		 nag, rec->notifyip);

    if ((num_hits = count_hits(r, remote_ip, (char *) sent_pw,
			       PWStr, &newFootprint,
			       interval, compareN, threshold, 1, rec)) == -1) {
      close_db(&db, r); 
      return -1; /* error in count_hits() */
    }

    if (newFootprint && /* changed in count_hits */
	(dataStr =
	combine_data_strings(r, newFootprint, BlockIgnoreStr, NULL, NULL))) {
      store_record(db, server_hostname, remote_ip /*key*/, dataStr, r);
    }

    close_db(&db, r);

    if (num_hits >= threshold) {
      if (nag) {
	if (rec->notifyip) {
	  send_mail(r, remote_ip, c->user, 
		    admin_email, server_hostname,
		    "iProtect Hacking notification",
		    "Password hacking attempt detected",
		    rec->auth_timeout, "seconds");
	}
      }
    } /* if (num_hits >= ... */

    if (num_hits > threshold) {
      LOG_PRINTF(s, "mod_iprot: threshold exceeded for: %s", remote_ip); 
      if (rec->external_progip != NULL) {
	ap_log_error (APLOG_MARK, APLOG_INFO, s,
		      "mod_iprot: calling external program %s",
		      rec->external_progip);
	call_external(r, remote_ip, rec->external_progip);
      }

      switch (rec->hack_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (rec->hack_redirect_url)
	  ap_internal_redirect(rec->hack_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    }
  } else {
    LOG_PRINTF(s, "mod_iprot: no record for IP %s, creating new record",
	       remote_ip);
    snprintf(buffer, BUFFER_LEN, "1?%s:%li", sent_pw,
	     (long) (r->request_time + interval));
    LOG_PRINTF(s, "mod_iprot: new record = %s", buffer);
    if ((dataStr =
	 combine_data_strings(r, buffer, BlockIgnoreStr, NULL, NULL)))
      store_record(db, server_hostname, remote_ip, dataStr, r);
    close_db(&db, r); 
  }
  
  return DECLINED;
} /* record_auth_attempt */

/* Passed basic auth, now we watch for successful logins from multiple
 * IP addresses for one username (abuse). */
static int record_access_attempt(request_rec *r)
{
  server_rec *s = r->server;
  conn_rec *c = r->connection;
  const char *server_hostname = ap_get_server_name(r);

  char *IPStr = "";
  char *failedIPStr = "";
  char *successfulIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";
  char *admin_email;
  char *abuse_email;
  char *hack_email;
  char *remote_ip;
  long interval;
  int compareN, num_hits, threshold, nag;
  char *newFootprint = NULL;

  DBM *db;
  datum d;

  prot_config_rec *rec =	/* get our module configuration record */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  LOG_PRINTF(s, "mod_iprot: record_access enabled_flag: %d", rec->enabled);

  if (!rec->enabled) return OK;

  /* get the real ip, if possible, otherwise go with r->remote_ip */
  remote_ip = lookup_header(r, "HTTP_X_FORWARDED_FOR");
  if (remote_ip == NULL) remote_ip = c->remote_ip;

  /* if the user or ip is in the ignore list, just ignore it... */
  if (match_string(r, rec->ignore_users, c->user)) return OK;
  if (match_string(r, rec->ignore_ips, remote_ip)) return OK;

  /* allow the IProtAbuseEmail to override the server admin, if set ???*/
  if (rec->abuse_email == NULL)
    admin_email = s->server_admin;
  else
    admin_email = rec->abuse_email;

  /* interval for IPs is in hours */
  if (rec->access_timeout == NULL || rec->threshold == NULL)
    return DECLINED;

  compareN = atoi(rec->compareN);
  interval = atol (rec->access_timeout) * 60 * 60;  
  threshold = atoi (rec->threshold);

  /* read a username record */
  if (!(db = open_db(rec->filename, IPROT_DB_FLAGS, 0664, r)))
    return OK;

  LOG_PRINTF(s, "mod_iprot: getting record for username %s", c->user);	
  if (!get_record(db, &d, server_hostname, c->user, r) ||
      !get_data_strings(r, &d, &IPStr, &failedIPStr, &BlockIgnoreStr, &BWStr) ||
      (strcmp(IPStr, "") && !(successfulIPStr =
		  PSTRDUP(r->pool, IPStr)))) { /* count_hits() changes IPStr */
    close_db(&db, r); 
    return OK;
  }

  /* check for block or ignore on user */
  if (strcmp(BlockIgnoreStr, "")) {
    switch (check_block_ignore(BlockIgnoreStr, db, server_hostname,
			       c->user, rec, r)) {
    case -1:	/* error or user ignored */
      close_db(&db, r); 
      return DECLINED;
    case 0:	/* no error or abuse, continue processing */
      break;
    case 1:	/* password cracking detected or blocked */
      close_db(&db, r); 
      switch (rec->hack_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (rec->hack_redirect_url)
	  ap_internal_redirect(rec->hack_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    }
  }

  if (strcmp(IPStr, "")) {
    /* If db record indicates no mail has yet been sent for this
     * entry, then send mail if a block is placed.
     * Otherwise, obey the config file.
     */
    if (index(IPStr, '\xbf') == NULL)  /* ¿ */
      nag = 1;
    else 
      nag = rec->nag;

    LOG_PRINTF(s, "mod_iprot: IPSTR = %s", IPStr);
    ap_log_error(APLOG_MARK, APLOG_INFO, s,
		 "mod_iprot: nag = %d notifyuser = %d",
		 nag, rec->notifyuser);

    if ((num_hits = count_hits(r, c->user, remote_ip, IPStr, &newFootprint,
			       interval, compareN, threshold, 1, rec)) == -1) {
      close_db(&db, r);
      return -1; /* error in count_hits() */
    }

    if (newFootprint) /* Changed in count_hits, save. */ {
      char *IPdata = NULL;
    
      if ((IPdata = combine_data_strings(r, newFootprint, failedIPStr,
					 BlockIgnoreStr, BWStr)))
	store_record(db, server_hostname, c->user, IPdata, r);
    }

    if (num_hits >= threshold) {
      /* blocking threshold reached, send email */
      LOG_PRINTF(s, "mod_iprot: threshold exceeded for: %s", c->user);
      if (nag) { 
	if (rec->notifyuser) {
	  send_mail(r, remote_ip, c->user, 
		    admin_email, server_hostname,
		    "iProtect Shared Access Abuse notification",
		    "Detected use of a shared password",
		    rec->access_timeout, "hours");	  
	}
      }
    } /* if (num_hits >= threshold ... */

    if (num_hits > threshold) {
      if (rec->external_proguser != NULL) {
	ap_log_error(APLOG_MARK, APLOG_INFO, s,
		     "mod_iprot: calling external program %s",
		     rec->external_proguser);
	call_external(r, c->user, rec->external_proguser);
      }

      close_db(&db, r);

      switch (rec->abuse_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (rec->abuse_redirect_url)
	  ap_internal_redirect(rec->abuse_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    } /* num_hits >= threshold */ else { /* num_hits < threshold */
      /* update timestamp */
      char *IPdata = NULL;

      if (newFootprint) /* changed in count_hits */
	newFootprint = update_timestamp(r, newFootprint, remote_ip,
					r->request_time + interval);
      else
	newFootprint = update_timestamp(r, successfulIPStr, remote_ip,
					r->request_time + interval);

      if ((IPdata = /* Memory allocated in function. */
	   combine_data_strings(r,
				newFootprint, failedIPStr,
				BlockIgnoreStr, BWStr)))
	store_record(db, server_hostname, c->user, IPdata, r);
      /* Don't store record if IPdata is NULL as we had an error. */
    }
  } else { /* no record found in db for user with successful logins */
#   undef BUFFER_LEN
#   define BUFFER_LEN 128
    char buffer[BUFFER_LEN];
    char *IPdata = NULL;

    LOG_PRINTF(s, "mod_iprot: no record for username %s detected, "
	       "creating new record", c->user);
    snprintf(buffer, BUFFER_LEN, "1?%s:%li", remote_ip,
	     (long) (r->request_time + interval));
    LOG_PRINTF(s, "mod_iprot: new record = %s", buffer);

    if ((IPdata =
	 combine_data_strings(r, buffer, failedIPStr, BlockIgnoreStr, BWStr)))
      store_record(db, server_hostname, c->user, IPdata, r);
  }

  close_db(&db, r);
  return OK; 
} /* record_access_attempt */

static void record_failed_auth_attempt(request_rec *r,
				       conn_rec *c,
				       server_rec *s,
				       prot_config_rec *config_rec,
				       const char *sent_pw,
				       const char *server_hostname)
{
  DBM *db;
  datum d;
  char *remote_ip;
  int num_hits;
  char *newFootprint = NULL;
  char *successfulIPStr = "";
  char *failedIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";
  long failed_interval = atol(config_rec->failed_timeout);
  int failed_threshold = atoi(config_rec->failed_threshold);
  int failed_compareN = atoi(config_rec->failed_compareN);

  /* get the proxy ip if one exists, otherwise go with r->remote_ip */
  remote_ip = lookup_header(r, "HTTP_X_FORWARDED_FOR");
  if (remote_ip == NULL) remote_ip = c->remote_ip;

  if (!(db = open_iprot_db(config_rec->filename, IPROT_DB_FLAGS, 0664, r)))
    return;

  /* Abort and return if fatal error. Caller ignores error and continues. */
  LOG_PRINTF(s, "mod_iprot: getting record for username %s", c->user);	
  if (!get_record(db, &d, server_hostname, c->user, r) ||
      !get_data_strings(r, &d, &successfulIPStr,
			&failedIPStr, &BlockIgnoreStr, &BWStr)) {
    close_db(&db, r);
    return;
  }

  if (strcmp(failedIPStr, "")) {
    int nag;

    if (index(failedIPStr, '\xbf') == NULL)  /* ¿ */
      nag = 1;
    else 
      nag = config_rec->nag;

    /* Record found for user with failed auth attempts. */
    LOG_PRINTF(s, "mod_iprot: failedIPStr = %s", failedIPStr);

    if ((num_hits = count_hits(r, c->user, remote_ip, failedIPStr,
			       &newFootprint, failed_interval,
			       failed_compareN, failed_threshold, 1,
			       config_rec)) == -1) {
      close_db(&db, r); 
      return; /* error in count_hits() */
    }

    if (newFootprint) { /* changed in count_hits */
      char *IPdata = NULL;

      if ((IPdata = combine_data_strings(r,
					 successfulIPStr,
					 newFootprint,
					 BlockIgnoreStr,
					 BWStr)))
	store_record(db, ap_get_server_name(r), c->user, IPdata, r);
    }

    if (num_hits >= failed_threshold) { 
      /* username is being abused, notify */
      const char *server_hostname = ap_get_server_name(r);
      char *admin_email;
      char *abuse_email;
      char *hack_email;

      /* allow the IProtEmail to override the server admin, if set. Could
	 this be moved to the configuration section?? ???*/
      if (config_rec->hack_email == NULL)
	admin_email = s->server_admin;
      else
	admin_email = config_rec->hack_email;

      if (nag) {
	if (config_rec->notifylogin) {
	  send_mail(r, remote_ip, c->user, 
		    admin_email, server_hostname,
		    "iProtect Failed Login notification",
		    "Too many failed logins for user detected",
		    config_rec->failed_timeout, "seconds");
	}
      }
    } /* if (num_hits >= ... */
  } else {
    /* No record found for user with failed auth attempts, create one. */
    char failedIPStr[128];
    char *IPdata = NULL;

    LOG_PRINTF(s, "mod_iprot: no record for username %s detected, "
	       "creating new record", c->user);
    snprintf(failedIPStr, 128, "1?%s:%li", remote_ip,
	     (long) (r->request_time + failed_interval));
    LOG_PRINTF(s, "mod_iprot: new record = %s", failedIPStr);

    if ((IPdata = combine_data_strings(r,
				       successfulIPStr,
				       failedIPStr,
				       BlockIgnoreStr,
				       BWStr)))
      store_record(db, ap_get_server_name(r), c->user, IPdata, r);
  }

  close_db(&db, r);
} /* record_failed_auth_attempt */

static int record_bytes_sent(request_rec *r)
{
  server_rec *s = r->server;
  conn_rec *c = r->connection;
  char *user = c->user;
  const char *server_hostname = ap_get_server_name(r);

  char *successfulIPStr = "";
  char *failedIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";

  DBM *db;
  datum d;

# undef BUFFER_LEN
# define BUFFER_LEN 32
  char buffer[BUFFER_LEN];
  char *dataStr = NULL;

  time_t timestamp;
  int total_bytes_sent = 0;
  char flag_char = S_CHAR;	/* separator char coding if
				/* email sent for block */

  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* if the user is in the ignore list, just ignore it... */
  if (match_string(r, config_rec->ignore_users, c->user))
    return TRUE;

  /* lots of requests don't have this, so don't even open the db */ 
  if (r->bytes_sent == 0)
    return TRUE;

  /* open database */
  if (!(db = open_iprot_db(config_rec->filename, IPROT_DB_FLAGS, 0664, r)))
    return -1; /* I/O Error */

  /* get user's data record and bw str */
  if (!(get_record(db, &d, server_hostname, c->user, r)) ||
      !(get_data_strings(r, &d,
			 &successfulIPStr, &failedIPStr,
			 &BlockIgnoreStr, &BWStr))) {
    close_db(&db, r); 
    return FALSE; /* I/O Error */
  }

  if (strcmp(BlockIgnoreStr, "") &&
      (BlockIgnoreStr[0] == 'B' || BlockIgnoreStr[0] == 'I')) {
    close_db(&db, r); 
    return TRUE;
  }

  /* update bw str */
  /* bytes:timestamp */
  if (strcmp(BWStr, "")) {
    if (sscanf(BWStr, "%i%c%i", &total_bytes_sent,
	       &flag_char, (int *)&timestamp) == 3) {
      total_bytes_sent += + r->bytes_sent;
      if (config_rec->bw_timeout)
	timestamp = r->request_time; /* update timestamp if not using
					daily bw limit */
    } else { 
      close_db(&db, r); 
      return FALSE;
    }
  } else {
    total_bytes_sent = r->bytes_sent;
    timestamp = r->request_time; /* timestamp is only set when there
				    is no existing record because we
				    keep track of bytes downloaded per
				    day */
  }

  /* make a new bw str */
  snprintf(buffer, BUFFER_LEN, "%i%c%i",
	   total_bytes_sent, flag_char, timestamp);

  /* store user's record */
  if ((dataStr =
       combine_data_strings(r, successfulIPStr, failedIPStr,
			    BlockIgnoreStr, buffer))) {
    store_record(db, server_hostname, c->user, dataStr, r);
  }

  close_db(&db, r);

  return TRUE;
} /* record_bytes_sent */

/* Check for failed login attempts here. This is the only chance to
 * check after authentication fails.
 *
 * Called after content or error message has been returned to the
 * browser so we can't check and block only on failed passwords.
 */
static int iprot_record(request_rec *r)
{
  conn_rec *c = r->connection;
  server_rec *s = r->server;
  const char *server_hostname = ap_get_server_name(r);
  const char *sent_pw;
  int auth_result;

  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* If authentication is not in use for this request exit. */
  if (!c->ap_auth_type) return DECLINED;

  auth_result = ap_get_basic_auth_pw(r, &sent_pw);

  switch (auth_result) {
  case OK:
    switch (r->status) {
    case HTTP_UNAUTHORIZED : { /* 401 */
      record_failed_auth_attempt(r, c, s, config_rec,
				 sent_pw, server_hostname);
      return DECLINED; /* incorrect user or password */
    }
    case HTTP_OK : { /* 200 */
      if (atoi(config_rec->max_bytes_user))
	record_bytes_sent(r);
      return DECLINED; /* correct user and password */
    }
    default:
      break;
    }
    break;
  case DECLINED:
    break; /* page not password protected, not found ... */
  case HTTP_INTERNAL_SERVER_ERROR:
    break;
  case HTTP_UNAUTHORIZED:
    break; /* no user name and password */
  default:
    break;
  }

  return DECLINED;
} /* iprot_record */


/* static addresses that we can use in a switch type statement to figure
   out which "set" function has been called... */

static int set_threshold, set_auth_timeout, set_access_timeout, set_file;
static int set_compare, set_ignore_ip, set_ignore_user;
static int set_email, set_abuse_email, set_hack_email, set_bw_email;
static int set_externalip, set_externaluser;
static int set_failed_threshold, set_failed_timeout, set_failed_compare;
static int set_abuse_redirect_url, set_hack_redirect_url;
static int set_block_ignore_file, set_max_bytes_user, set_bw_redirect_url;

static const char *set_var(cmd_parms *cmd, void *dummy, char *t)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  
  if (&set_threshold == cmd->info) {
    if (!(config_rec->threshold = PSTRDUP(cmd->pool, t)))
      server_init_abort(cmd->server);
  } else
    if (&set_auth_timeout == cmd->info) {
      if (!(config_rec->auth_timeout = PSTRDUP(cmd->pool, t)))
	server_init_abort(cmd->server);	 
    } else
      if (&set_access_timeout == cmd->info) {
	if (!(config_rec->access_timeout = PSTRDUP(cmd->pool, t)))
	  server_init_abort(cmd->server);
      } else
	if (&set_file == cmd->info) {
	  if (!(config_rec->filename = ap_server_root_relative(cmd->pool, t)))
	    server_init_abort(cmd->server);
	} else
	  if (&set_compare == cmd->info) {
	    if (!(config_rec->compareN = PSTRDUP(cmd->pool, t)))
	      server_init_abort(cmd->server);
	  } else
	    if (&set_ignore_user == cmd->info) {
	      ap_table_setn(config_rec->ignore_users, t, t);
	    } else
	      if (&set_ignore_ip == cmd->info) {
		ap_table_setn(config_rec->ignore_ips, t, t);
	      } else
		if (&set_email == cmd->info) {
		  if (!(config_rec->email = PSTRDUP(cmd->pool, t)))
		    server_init_abort(cmd->server);
		  if (!config_rec->abuse_email)
		    config_rec->abuse_email = config_rec->email;
		  if (!config_rec->hack_email)
		    config_rec->hack_email = config_rec->email;
		  if (!config_rec->bw_email)
		    config_rec->bw_email = config_rec->email;
		} else
		  if (&set_abuse_email == cmd->info) {
		    if (!(config_rec->abuse_email = PSTRDUP(cmd->pool, t)))
		      server_init_abort(cmd->server);
		  } else
		    if (&set_hack_email == cmd->info) {
		      if (!(config_rec->hack_email = PSTRDUP(cmd->pool, t)))
			server_init_abort(cmd->server);
		    } else
		      if (&set_bw_email == cmd->info) {
			if (!(config_rec->bw_email = PSTRDUP(cmd->pool, t)))
			  server_init_abort(cmd->server);
		      } else
			if (&set_externalip == cmd->info) {
			  if (!(config_rec->external_progip =
				PSTRDUP(cmd->pool, t)))
			    server_init_abort(cmd->server);  
			} else
			  if (&set_externaluser == cmd->info) {
			    if (!(config_rec->external_proguser =
				  PSTRDUP(cmd->pool, t)))
			      server_init_abort(cmd->server);
			  } else
			    if (&set_failed_threshold == cmd->info) {
			      if (!(config_rec->failed_threshold =
				    PSTRDUP(cmd->pool, t)))
				server_init_abort(cmd->server);  
			    } else
			      if (&set_failed_timeout == cmd->info) {
				if (!(config_rec->failed_timeout =
				      PSTRDUP(cmd->pool, t)))
				  server_init_abort(cmd->server);	 
			      } else
				if (&set_failed_compare == cmd->info) {
				  if (!(config_rec->failed_compareN =
					PSTRDUP(cmd->pool, t)))
				    server_init_abort(cmd->server);  
				} else
				  if (&set_abuse_redirect_url == cmd->info) {
				    if (!(config_rec->abuse_redirect_url =
					  PSTRDUP(cmd->pool, t)))
				      server_init_abort(cmd->server);
				  } else
				    if (&set_hack_redirect_url == cmd->info) {
				      if (!(config_rec->hack_redirect_url =
					    PSTRDUP(cmd->pool, t)))
					server_init_abort(cmd->server);
				    } else
				      if (&set_block_ignore_file == cmd->info) {
					if (!(config_rec->block_ignore_filename =
					      ap_server_root_relative(cmd->pool,
								      t)))
					  server_init_abort(cmd->server);	 
				      } else
					if (&set_max_bytes_user == cmd->info) {
					  if (!(config_rec->max_bytes_user =
						PSTRDUP(cmd->pool, t)))
					    server_init_abort(cmd->server);
					} else
					  if (&set_bw_redirect_url ==
					      cmd->info) {
					    if (!(config_rec->bw_redirect_url =
						  PSTRDUP(cmd->pool, t)))
					      server_init_abort(cmd->server);
					  }
  return NULL;
} /* set_var */

static const char *set_nag(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->nag = val;
  return NULL;
}

static const char *set_enabled(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->enabled = val;
  return NULL;
}

static const char *set_notifyip(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->notifyip= val;
  return NULL;
}

static const char *set_notifybw(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->notifybw= val;
  return NULL;
}

static const char *set_notifyuser(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->notifyuser = val;
  return NULL;
}

static const char *set_notifylogin(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->notifylogin = val;
  return NULL;
}

static const char *set_abuse_status_return(cmd_parms *cmd,
					   void *dummy,
					   const char *val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->abuse_status_return = atoi(val);
  return NULL;
}

static const char *set_hack_status_return(cmd_parms *cmd,
					  void *dummy,
					  const char *val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->hack_status_return = atoi(val);
  return NULL;
}

static const char *set_bw_status_return(cmd_parms *cmd,
					void *dummy,
					const char *val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->bw_status_return = atoi(val);
  return NULL;
}

static const char *set_bw_timeout(cmd_parms *cmd,
				  void *dummy,
				  const char *val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->bw_timeout = atoi(val);
  return NULL;
}

static const char *set_no_HEAD_req(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->no_HEAD_req = val;
  return NULL;
}

static const char *set_all_hosts_admin(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  config_rec->all_hosts_admin = val;
  return NULL;
}


/* table of configuration variables */
static const command_rec prot_cmds[] = {
  {"IProtThreshold", set_var, &set_threshold, RSRC_CONF, TAKE1,
   "Number of different ips to allow for each user."},
  {"IProtAuthTimeout", set_var, &set_auth_timeout, RSRC_CONF, TAKE1,
   "Number of seconds to keep records of user authentication."},
  {"IProtAccessTimeout", set_var, &set_access_timeout, RSRC_CONF, TAKE1,
   "Number of hours to keep records of user access."},
  {"IProtCompareN", set_var, &set_compare, RSRC_CONF, TAKE1,
   "Number of octets in IP addr to compare ([1-4])."},
  {"IProtEmail", set_var, &set_email, RSRC_CONF, TAKE1,
   "EMail address to send abuse/hack notifications."},
  {"IProtFailedThreshold", set_var, &set_failed_threshold, RSRC_CONF, TAKE1,
   "Number of IP addresses with failed logins to allow for each user."},
  {"IProtFailedTimeout", set_var, &set_failed_timeout, RSRC_CONF, TAKE1,
   "Number of hours to keep records of failed logins."},
  {"IProtFailedCompareN", set_var, &set_failed_compare, RSRC_CONF, TAKE1,
   "Number of octets in IP addresses to compare on failed logins."},
  {"IProtNotifyUser", set_notifyuser, NULL, RSRC_CONF, FLAG,
   "If On, send email when a user trips the shared user/password abuse"
   " detector, otherwise just block the user."
   "Default is On, enabled."},
  {"IProtNotifyLogin", set_notifylogin, NULL, RSRC_CONF, FLAG,
   "If On, send email when a user trips the failed login detector,"
   " otherwise just block them. "
   "Default is On, enabled."},
  {"IProtAbuseStatusReturn", set_abuse_status_return, NULL, RSRC_CONF, TAKE1,
   "For abuse blocks - "
   "0: no status returned, "
   "1: FORBIDDEN status returned, "
   "2: redirect to IProtAbuseRedirectURL."},
  {"IProtAbuseRedirectURL", set_var, &set_abuse_redirect_url, RSRC_CONF, TAKE1,
   "URL to redirect 403 FORBIDDEN Errors to for abuses."},
  {"IProtAbuseEmail", set_var, &set_abuse_email, RSRC_CONF, TAKE1,
   "EMail address to send abuse notifications."},
  {"IProtHackStatusReturn", set_hack_status_return, NULL, RSRC_CONF, TAKE1,
   "For password hacking blocks - "
   "0: no status returned, "
   "1: FORBIDDEN status returned, "
   "2: redirect to IProtRedirectURL."},
  {"IProtHackRedirectURL", set_var, &set_hack_redirect_url, RSRC_CONF, TAKE1,
   "URL to redirect 403 FORBIDDEN Errors to for hacks."},
  {"IProtHackEmail", set_var, &set_hack_email, RSRC_CONF, TAKE1,
   "EMail address to send hack notifications."},
  {"IProtNotifyIP", set_notifyip, NULL, RSRC_CONF, FLAG,
   "If On, send email when a user trips the hack detector,"
   " otherwise just block them. "
   "Default is On, enabled."},
  {"IProtMaxBytesUser", set_var, &set_max_bytes_user, RSRC_CONF, TAKE1,
   "Max bytes of transfer per user per day (bandwidth) in megabytes. "
   "Default is 0, unlmited."},
  {"IProtBWStatusReturn", set_bw_status_return, NULL, RSRC_CONF, TAKE1,
   "For bandwidth blocks - "
   "0: no status returned, "
   "1: FORBIDDEN status returned, "
   "2: redirect to IProtRedirectURL."},
  {"IProtBWRedirectURL", set_var, &set_bw_redirect_url, RSRC_CONF, TAKE1,
   "URL to redirect 403 FORBIDDEN Errors to for exceeding daily bandwidth."},
  {"IProtBWEmail", set_var, &set_bw_email, RSRC_CONF, TAKE1,
   "EMail address to send bandwidth notifications."},
  {"IProtNotifyBW", set_notifybw, NULL, RSRC_CONF, FLAG,
   "if On, send email when a user trips the daily bandwidth block,"
   " otherwise just block them. "
   "Default is On, enabled."},
  {"IProtBWTimeout", set_bw_timeout, NULL, RSRC_CONF, TAKE1,
   "Timeout for bandwidth blocks. If 0 blocks last until the end of the"
   " calendar day in which they were placed."},
  {"IProtEnable", set_enabled, NULL, RSRC_CONF, FLAG,
   "Off to disable checking for this virtual host. "
   "Default is On, enabled."},
  {"IProtNag", set_nag, NULL, RSRC_CONF, FLAG,
   "If On, send email every time a user/IP address trips the detector,"
   " otherwise just send one mail when a block is set."},  
  {"IProtExternalIP", set_var, &set_externalip, RSRC_CONF, TAKE1,
   "External program to execute in addition to sendmail"
   " when an IP address is banned. "
   " First argument passed to the program is the client ip."},
  {"IProtExternalUser", set_var, &set_externaluser, RSRC_CONF, TAKE1,
   "External program to execute in addition to sendmail. "
   " when a username address is banned. "
   "First argument passed to the program is the username."},
  {"IprotIgnoreIP", set_var, &set_ignore_ip, RSRC_CONF, ITERATE,
   "IP addresse to ignore, one per directive."},
  {"IProtIgnoreUser", set_var, &set_ignore_user, RSRC_CONF, ITERATE,
   "Username to ignore, one per directive."},
  {"IProtNoHEADReq", set_no_HEAD_req, NULL, RSRC_CONF, FLAG,
   "On: drop connection on all HEAD requests, "
   "Off: handle HEAD requests normally. Default is Off."},
  {"IProtAllHostsAdmin", set_all_hosts_admin, NULL, RSRC_CONF, FLAG,
   "On: Show all virtual hosts in iProt Admin, "
   "Off: Show only current host in iProt Admin. Default is Off."},
  {"IProtDBFile", set_var, &set_file, RSRC_CONF, TAKE1,
   "db file to store access data."},
  {"IProtBlockIgnoreDBFile", set_var, &set_block_ignore_file, RSRC_CONF, TAKE1,
   "Database file to store user placed block and ignore data."},
  {NULL}
}; /* command_rec */

/* Make the name of the content handler known to Apache */
static handler_rec handlers[] = {
  {"iprot-admin", iprot_admin},
  {NULL}
};

module MODULE_VAR_EXPORT iprot_module = {
  STANDARD_MODULE_STUFF,
#if 0
  mod_init,		/* module initializer			     */
#else
  NULL,			/* module initializer			     */
#endif
  NULL,			/* per-directory config creater		     */
  NULL,			/* dir config merger - default is override   */
  create_prot_config,	/* server config creator		     */
  merge_prot_config,	/* server config merger - virtual host stuff */
  prot_cmds,		/* config directive (command) table	     */
  handlers,		/* [9]	content handlers		     */
  NULL,			/* [2]	URI-to-filename translation	     */
  record_auth_attempt,	/* [5]	check/validate user_id		     */
  record_access_attempt,/* [6]	check user_id is valid here (auth)   */
  NULL,			/* [4]	check access by host address	     */
  NULL,			/* [7]	MIME type checker/setter	     */
  NULL,			/* [8]	fixups				     */
  iprot_record,		/* [10] logger				     */
  NULL,			/* [3]	header parser			     */
  NULL,			/* process initialization child_init	     */
  NULL,			/* process exit/cleanup child_exit	     */
  NULL			/* [1]	post read-request		     */
};

/*
 * record_auth_attempt() multiple login attempts from one IP.
 * record_access_attempt() multiple IP addresses with one username.
 *  
 * Failed password attempts are recorded in iprot_record().
 * record_failed_auth_attempt()
 */
