/*
 * iProtect for Apache
 *
 * Copyright 1999-2003, Digital Concepts
 *
 * http://www.digital-concepts.net
 */

#include "mod_iprot.h"
#include "http_request.h"


/* Log a fatal error and abort during server initialization. */
static void server_init_abort(server_rec *s)
{
  ap_log_error(APLOG_MARK, APLOG_CRIT, s, "Aborting httpd!");
  exit(errno);
}

static void mod_init(server_rec *s, pool *p)
{
  server_rec *sp = s;
  char *db_directory = NULL;
  DB_ENV *db_envp;

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s, "========");
  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "compiled: %s %s", __DATE__, __TIME__);
  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "mod_init(1): pid %i, uid %i, gid %i, euid %i, egid %i",
	       (int)getpid(), (int)getuid(), (int)getgid(),
	       (int)geteuid(), (int)getegid());
  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "mod_init(2): server uid %i, server gid %i",
	       s->server_uid, s->server_gid);

  /*kill(getpid(), SIGSTOP);*/

  /* If server is running as root we have to switch uid and gid 
   * while we check the database environment.
   * <slePP> c-wheeler: just use seteuid/setegid
   */

  if (!getuid()) { /* running as root */
    if (setegid(s->server_gid)) {
      ap_log_error(APLOG_MARK, APLOG_ERR, s, "mod_init(2a): switching gid");
      goto abort;
    }
    if (seteuid(s->server_uid)) {
      ap_log_error(APLOG_MARK, APLOG_ERR, s, "mod_init(2b): switching uid");
      goto abort;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "mod_init(2c): pid %i, euid %i, egid %i",
		 (int)getpid(), (int)geteuid(), (int)getegid());
  }

  while (sp) {
    prot_config_rec *conf_rec =	/* get our module configuration record */
      (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);
    if (!conf_rec) server_init_abort(s);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "mod_init(3): server_name: %s, pid %i",
		 sp->server_hostname, (int)getpid());

    db_directory = (char *)PSTRDUP(p, conf_rec->block_ignore_filename);
    if (!db_directory) server_init_abort(s);  /* ENOMEN */
    db_directory = dirname(db_directory);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "mod_init(4): filename(): %s,"
		 " block_ignore_filename: %s, "
		 "db_directroy: %s",
		 conf_rec->filename,
		 conf_rec->block_ignore_filename,
		 db_directory);

    /* create database environment */
    if ((db_envp =
	 create_db_env(db_directory, DB_RECOVER, IPROT_DB_PERMS, s)) == NULL) {
      goto abort;
    }
    /* open and close database environment to run recovery. */
    close_db_env(&db_envp, s);	/* s is passed only for loggin */
				/* using sp breaks things */
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s, "--------");
    sp = sp->next;
  } /* while */

abort:
  if (!getuid()) { /* running as root */
    if (seteuid(0)) {
      ap_log_error(APLOG_MARK, APLOG_ERR, s, "mod_init(4a): switching uid");
    }
    if (setegid(0)) {
      ap_log_error(APLOG_MARK, APLOG_ERR, s, "mod_init(4b): switching gid");
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "mod_init(4c): pid %i, euid %i, egid %i",
		 (int)getpid(), (int)geteuid(), (int)getegid());
  }

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "mod_init(5): done: pid %i", (int)getpid());
  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "========");
} /* mod_init */

void child_init(server_rec *s, pool *p)
{
  server_rec *sp = s;
  char *db_directory = NULL;

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "child_init(1): pid %i, euid %i, egid %i",
	       (int)getpid(), (int)geteuid(), (int)getegid());

  while (sp) {
    prot_config_rec *conf_rec =	/* get our module configuration record */
      (prot_config_rec *) GET_MODULE_CONFIG(sp->module_config, &iprot_module);
    if (!conf_rec) server_init_abort(s);  /* s is passed only for loggin */
					  /* using sp breaks things */
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "child_init(2): server_name: %s, pid %i",
		 sp->server_hostname, (int)getpid());

    db_directory = (char *)PSTRDUP(p, conf_rec->block_ignore_filename);
    if (!db_directory) server_init_abort(s);  /* ENOMEN */
    db_directory = dirname(db_directory);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "child_init(3): filename(2): %s,"
		 " block_ignore_filename: %s, "
		 "db_directroy: %s",
		 conf_rec->filename,
		 conf_rec->block_ignore_filename,
		 db_directory);
 
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "child_init(4): create_db_env: %s pid %i",
		 db_directory, (int)getpid());

    /* create database environment */
    if ((conf_rec->db_envp =
	 create_db_env(db_directory, 0, IPROT_DB_PERMS, s)) == NULL) {
      return;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "child_init(5): open_db: %s pid %i",
		 conf_rec->filename, (int)getpid());

    /* open block ignore database */
    conf_rec->iprot_db =
      open_db(conf_rec->db_envp, conf_rec->filename,
	      DB_CREATE, IPROT_DB_PERMS, s);  /* s is passed only for loggin */
						/* using sp breaks things */
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "child_init(6): open_db: %s pid %i",
		 conf_rec->block_ignore_filename, (int)getpid());

    /* open iprot database */
    conf_rec->block_ignore_db =
      open_db(conf_rec->db_envp, conf_rec->block_ignore_filename,
	      DB_CREATE, IPROT_DB_PERMS, s);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s, "--------");
    sp = sp->next;
  } /* while */

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "child_init(7) done: pid %i", (int)getpid());

} /* child_init */

void child_exit(server_rec *s, pool *p)
{
  server_rec *sp = s;

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "child_exit(1): pid %i, euid %i, egid %i",
	       (int)getpid(), (int)geteuid(), (int)getegid());

  while (sp) {
    prot_config_rec *conf_rec =	/* get our module configuration record */
      (prot_config_rec *) GET_MODULE_CONFIG(sp->module_config, &iprot_module);
    if (!conf_rec) server_init_abort(s);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "child_exit(2): server_name: %s", sp->server_hostname);

    close_db(&conf_rec->iprot_db, s);	/* s is passed only for loggin */
					/* using sp breaks things */
    close_db(&conf_rec->block_ignore_db, s);

    close_db_env(&conf_rec->db_envp, s);

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s, "--------");
    sp = sp->next;
  } /* while */

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "child_exit(3): done: pid %i", (int)getpid());
} /* child_exit */

/* function to initialize server config structure */
static void *create_prot_config(pool *p, server_rec *s)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *)PALLOC(p, sizeof(prot_config_rec));
  if (!conf_rec) server_init_abort(s);

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "create_prot_config(): pid %i", (int)getpid());

  conf_rec->threshold = IPROT_THRESHOLD;       /* num hits */
  conf_rec->auth_timeout = IPROT_AUTH_TIMEOUT; /* timeout for authorizations */
  conf_rec->access_timeout = IPROT_ACCESS_TIMEOUT; /* timeout for accesses */

  conf_rec->compareN = IPROT_COMPARE_N;

  conf_rec->external_progip = NULL;
  conf_rec->external_proguser = NULL;

  conf_rec->email = NULL;
  conf_rec->abuse_email = NULL;
  conf_rec->hack_email = NULL;
  conf_rec->bw_email = NULL;

  conf_rec->failed_threshold = IPROT_FAILED_THRESHOLD;
					/* threshold number of ips for
					 * failed login for one user */
  conf_rec->failed_timeout = IPROT_FAILED_TIMEOUT;
					/* timeout for failed logins */
  conf_rec->failed_compareN = IPROT_FAILED_COMPARE_N;

  if (!(conf_rec->filename = (char *) PSTRDUP(p, IPROT_DB_FILE)))
    server_init_abort(s);
  if (!(conf_rec->block_ignore_filename =
	(char *) PSTRDUP(p, IPROT_BLOCKIGNORE_DB_FILE)))
    server_init_abort(s);

  conf_rec->abuse_status_return = IPROT_ABUSE_STATUS_RETURN;
				/* return HTTP STATUS Forbidden (403) */
  conf_rec->hack_status_return = IPROT_HACK_STATUS_RETURN;
				/* status by default */
  conf_rec->abuse_redirect_url = IPROT_ABUSE_REDIRECT_URL;
  conf_rec->hack_redirect_url = IPROT_HACK_REDIRECT_URL;

  conf_rec->bw_status_return = IPROT_BW_STATUS_RETURN;
				/* return HTTP STATUS Forbidden (403) 
				 * status by default */
  conf_rec->max_bytes_user = IPROT_MAX_BYTES_USER;  /* default is disabled */
  conf_rec->bw_timeout = IPROT_BW_TIMEOUT;

  conf_rec->bw_redirect_url = NULL;

  conf_rec->nag = IPROT_NAG;  	/* sent email every time a user/ip
				 * is blocked */
  conf_rec->notifyip = IPROT_NOTIFY_IP;        /* send hack attempt
						* mail by default */
  conf_rec->notifyuser = IPROT_NOTIFY_USER;    /* send abuse mail by default */
  conf_rec->notifylogin = IPROT_NOTIFY_LOGIN;  /* send failed login mail
						* by default */
  conf_rec->notifybw = IPROT_NOTIFY_BW;	  /* send bw block mail by default */

  conf_rec->enabled = IPROT_ENABLED;	  /* enabled by default */
  conf_rec->no_HEAD_req = IPROT_NO_HEAD_REQ;	/* process HEAD requests
						 * by default */
  conf_rec->all_hosts_admin = IPROT_ALL_HOSTS_ADMIN;  /* show all hosts in
						       * admin off by default */

  if (!(conf_rec->ipaddress_preg =
	ap_pregcomp(p, IPROT_IPADDRESS_PREG, REG_EXTENDED | REG_NOSUB)) ||
      !(conf_rec->ignore_ips = ap_make_table(p, 20)) ||
	!(conf_rec->ignore_users = ap_make_table(p, 20)))
    server_init_abort(s);

  return (void *)conf_rec;
} /* create_prot_config */

/* function to initialize virtual server config structure */
static void *merge_prot_config(pool *p, void *basev, void *newv)
{
  prot_config_rec *base, *new;
  array_header *arr;

  base = (prot_config_rec *)basev;
  new = (prot_config_rec *)newv;
  
  new->threshold =
    new->threshold != IPROT_THRESHOLD ?
    new->threshold : base->threshold;
  new->auth_timeout =
    new->auth_timeout != IPROT_AUTH_TIMEOUT ?
    new->auth_timeout : base->auth_timeout;
  new->access_timeout =
    new->access_timeout != IPROT_ACCESS_TIMEOUT ?
    new->access_timeout : base->access_timeout;
  new->filename =
    strcmp(new->filename, IPROT_DB_FILE) ?
    new->filename : base->filename;
  new->compareN =
    new->compareN != IPROT_COMPARE_N ?
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
    new->failed_threshold != IPROT_FAILED_THRESHOLD ?
    new->failed_threshold : base->failed_threshold;
  new->failed_timeout =
    new->failed_timeout != IPROT_FAILED_TIMEOUT ?
    new->failed_timeout : base->failed_timeout;
  new->failed_compareN =
    new->failed_compareN != IPROT_FAILED_COMPARE_N ?
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
    new->max_bytes_user != IPROT_MAX_BYTES_USER ?
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

#if DEBUG
static int post_read_request(request_rec *r)
{
  server_rec *s = r->server;

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "post_read_request, pid: %i, hostname: %s, uri: %s",
	       (int)getpid(), r->hostname, r->unparsed_uri);
  return DECLINED;
} /* post_read_request */
#endif

static void send_mail(request_rec *r,
		      const char *ip, const char *target,
		      const char *email, const char *host,
		      const char *subject, const char *message,
		      const int expires_1, const char *expires_2)
{
  server_rec *s = r->server;
# define BUFFER_LEN 256
  char buffer[BUFFER_LEN];
  FILE *pi;
  const time_t timestamp = r->request_time;
		      
  ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s,
	       "sending email to %s", email);
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
  fprintf(pi, "expires in: %i %s.\n", expires_1, expires_2);

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
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "update_timestamp()");
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
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "count_hits()");
    return -1;
  }

  /* This will prune the list of expired entries. */
  num_items = get_footprint_list(footprintStr, footprint_list,
				 (long) r->request_time, &exp);

  /* If we're over the threshold after prune, don't bother continuing. */
  if (num_items > threshold) {
    ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s,
		 "count %d exceeds threshold %d, "
		 "blocking immediately.",
		 num_items, threshold);
    *newFootprint = NULL;
    return num_items;	 /* bad user */
  }

  if (!(*newFootprint = /* Space for 1 new item. */
	(char *) PALLOC(r->pool, 20 + strlen(item) + footprintStr_len))) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "count_hits()");
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
				      prot_config_rec *conf_rec,
				      const char *remote_ip,
				      const char *admin_email/*,
				      const char *abuse_email,
				      const char *hack_email???*/)
{
  DB_TXN *txn_id;
  DBT d;
  char *newFootprint = NULL;
  char *successfulIPStr = "";
  char *failedIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";
  int count, nag;
  const char *server_name = ap_get_server_name(r);
  int status;
  int result;

  /* abort and retry */
  if (FALSE) {
  retry:
    transaction_abort(s, txn_id);
  }

  /* transaction_start */
  if ((result = transaction_start(s, conf_rec->db_envp,
				  NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, s, db_strerror(result));
    return -1;
  }

  if ((result = get_record(txn_id, conf_rec->iprot_db, &d,
			   server_name, c->user, r)) != 0) {
    if (result != DB_NOTFOUND) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	return -1; /* I/O Error */
      }
    }
  }

  if (!(get_data_strings(r, &d,
			 &successfulIPStr,
			 &failedIPStr,
			 &BlockIgnoreStr,
			 &BWStr))) {
    transaction_abort(s, txn_id);
    return -1; /* I/O Error */
  }

  /* Check for block or ignore on user. */
  if (strcmp(BlockIgnoreStr, "")) {
    int block_status;

    if ((block_status = check_block_ignore(BlockIgnoreStr,
					   server_name, c->user, r))) {
      transaction_abort(s, txn_id);
      return block_status; /* blocked, ignored, or error */
    }
  }

  if (strcmp(failedIPStr, "")) {
    /* if db record indicates no mail has yet been sent for this entry,
       then send something. otherwise, obey the config file */
    if (index(failedIPStr, '\xbf') == NULL)  /* ¿ */
      nag = 1;
    else 
      nag = conf_rec->nag;

    if ((count = count_hits(r, c->user, remote_ip,
			    failedIPStr, &newFootprint,
			    conf_rec->failed_timeout,/*interval*/
			    conf_rec->compareN,
			    conf_rec->failed_threshold, 0, conf_rec)) == -1) {
      transaction_abort(s, txn_id);
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
	transaction_abort(s, txn_id);
	return -1;
      }

      if ((result =
	   store_record(txn_id, conf_rec->iprot_db,
			server_name, c->user, IPdata, r)) != 0) {
	if (result == DB_LOCK_DEADLOCK) {
	  goto retry;
	} else {
	  transaction_abort(s, txn_id);
	  return -1;
	}
      }

      transaction_commit(s, txn_id, 0);
    } else {
      transaction_abort(s, txn_id);
    }

    if (count >= conf_rec->failed_threshold) {
      char *cmp_ip;

      /* check for recent successful logins from this ip */
      if (!(cmp_ip = (char *) PALLOC(r->pool, strlen(remote_ip) + 1))) {
	/* out of memory */
	ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s",
		      "check_failed_auth_attempts()");
	return -1;
      }
      strcpy(cmp_ip, "");

      if (conf_rec->compareN < 4) {
	char *tmp_ip, *oct;
	int i;

	tmp_ip = (char *) PALLOC(r->pool, strlen(remote_ip) + 1);
	if (!tmp_ip) {
	  /* out of memory */
	  ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s",
			"check_failed_auth_attempts()");
	  return -1;
	}
	strcpy(tmp_ip, remote_ip);

	oct = strtok(tmp_ip, ".");
	for (i = 0; i < conf_rec->compareN; i++) {
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
	ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s,
		     "mod_iprot: failed login threshold "
		     "exceeded for: %s at server %s",
		     c->user, server_name); 

	if (conf_rec->external_progip != NULL) {
	  ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s,
		       "mod_iprot: calling external program %s",
		       conf_rec->external_progip);
	  call_external(r, remote_ip,
			conf_rec->external_progip);
	}

	status = (count > conf_rec->failed_threshold) ? 1 : 0;
      }
    } else {
      status = 0;
    }
  } else {
    transaction_abort(s, txn_id);
    status = 0; /* no record of this ip */
  }

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

  DB_TXN *txn_id;
  DBT d;
  int result;

  int rtn = 0; /* return value -1: error, 0: not blocked, 1: blocked */
  time_t timestamp = 0;
  int total_bytes_sent;
  char flag_char;

  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* abort and retry */
  if (FALSE) {
  retry:
    transaction_abort(s, txn_id);
  }

  /* transaction_start */
  if ((result = transaction_start(s, config_rec->db_envp,
				  NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    return -1;
  }

  /* get user's data record and bw str */
  if ((result = get_record(txn_id, config_rec->iprot_db, &d,
			   server_hostname, c->user, r)) != 0) {
    if (result != DB_NOTFOUND) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	return -1; /* I/O Error */
      }
    }
  }

  if (!(get_data_strings(r, &d,
			 &successfulIPStr, &failedIPStr,
			 &BlockIgnoreStr, &BWStr))) {
    transaction_abort(s, txn_id);
    return -1; /* I/O Error or out of memory*/
  }

  if (strcmp(BWStr, "")) {
    if (sscanf(BWStr, "%i%c%i", &total_bytes_sent,
	       &flag_char, (int *)&timestamp) == 3) {

      if ((config_rec->bw_timeout &&
	   periodic_block_expired(timestamp,
				  config_rec->bw_timeout,
				  r->request_time)) /* periodic block? */ ||
	  diff_day(timestamp, r->request_time)) {  /* new calendar day? */
	char *dataStr = NULL;
	/* store user's record with zeroed bw data, record_bytes_sent
	   will create a new record with a new date */
	if ((dataStr =
	     combine_data_strings(r, successfulIPStr, failedIPStr,
				  BlockIgnoreStr, ""))) {
	  if ((result =
	       store_record(txn_id, config_rec->iprot_db,
			    server_hostname, c->user, dataStr, r)) != 0) {
	    if (result == DB_LOCK_DEADLOCK) {
	      goto retry;
	    } else {
	      transaction_abort(s, txn_id);
	      return FALSE;
	    }
	  }
	} else {
	  transaction_abort(s, txn_id);
	  return FALSE;
	}
      } else {
	if (total_bytes_sent > (config_rec->max_bytes_user * MBYTE)) {
	  /* user has exceeded maximum transfer */

	  rtn = TRUE;
	  /* send email ? */
	  if (((flag_char == S_CHAR) || config_rec->nag) &&
	      config_rec->notifybw) {
	    char *admin_email =
	      (config_rec->bw_email == NULL) ?
	      s->server_admin : config_rec->bw_email;

	    /* get the real ip, if possible,
	     * otherwise go with c->remote_ip */
	    char *remote_ip = lookup_header(r, "HTTP_X_FORWARDED_FOR");
	    if (remote_ip == NULL) remote_ip = c->remote_ip;

	    if (config_rec->bw_timeout) {
	      send_mail(r, remote_ip, c->user, 
			admin_email, server_hostname,
			"iProtect BandWidth notification",
			"Daily BandWidth exceeded for user",
			config_rec->bw_timeout, "hours");
	    } else {
	      send_mail(r, remote_ip, c->user, 
			admin_email, server_hostname,
			"iProtect BandWidth notification",
			"Daily BandWidth exceeded for user",
			1, "day");
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
		if ((result =
		     store_record(txn_id, config_rec->iprot_db,
				  server_hostname,
				  c->user, dataStr, r) ) != 0) {
		  if (result == DB_LOCK_DEADLOCK) {
		    goto retry;
		  } else {
		    transaction_abort(s, txn_id);
		    return FALSE;
		  }
		}
	      } else {
		transaction_abort(s, txn_id);
		return FALSE;
	      }
	    }
	  } /* send email */
	}
      }
    } /* if (sscanf(BWStr, ... */ else {
      rtn = -1; /* error scanning string */
    }
  } /* if (strcmp(BWStr, "")) */

  transaction_commit(s, txn_id, 0);
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
# undef BUFFFER_LEN
# define BUFFFER_LEN 128
  char buffer[BUFFFER_LEN];
  int res, num_hits, nag;
  char *remote_ip;
  char *newFootprint = NULL;

  DB_TXN *txn_id;
  DBT d;
  int result;

  prot_config_rec *conf_rec =	/* module config rec */
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

  LOG_PRINTF(s, "mod_iprot: record_auth enabled_flag = %d", conf_rec->enabled);

  if (!conf_rec->enabled)  /* enable flag is not set */
    return DECLINED;

  /* if the user is in the ignore list, just ignore it... */
  if (match_string(r, conf_rec->ignore_users, c->user))
    return DECLINED;

  /* if the ip is in the ignore list, just ignore it... */
  if (match_string(r, conf_rec->ignore_ips, remote_ip))
    return DECLINED;

  if (r->header_only && conf_rec->no_HEAD_req)
    return DONE; /* HEAD request, close connection w/o returning anything. */
		 /* Do this here so we only affect requests for pages */
		 /* requiring authentication. */

  /* allow the IProtEmail to override the server admin, if set. Could
     this be moved to the configuration section???*/
  if (conf_rec->hack_email == NULL)
    admin_email = s->server_admin;
  else
    admin_email = conf_rec->hack_email;

  /* check for number of failed logins from different ips */
  if (conf_rec->failed_timeout && conf_rec->failed_threshold)
    switch (check_failed_auth_attempts(r, c, s, conf_rec,
				       remote_ip, admin_email)) {
    case -1:	/* error or user ignored */
      return DECLINED;
    case 0:	/* no error or abuse, continue processing */
      break;
    case 1:	/* password cracking blocked */
      switch (conf_rec->hack_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (conf_rec->hack_redirect_url)
	  ap_internal_redirect(conf_rec->hack_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    }

  /* check for bandwidth used */
  if (conf_rec->max_bytes_user)
    switch (check_bandwidth(r)) {
    case -1:	/* error */
      return DECLINED;
    case 0:	/* no error or abuse, continue processing */
      break;
    case 1:	/* password cracking blocked */
      switch (conf_rec->bw_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (conf_rec->bw_redirect_url)
	  ap_internal_redirect(conf_rec->bw_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    }

  /* interval for login attempts is in seconds, not hours */
  if (!conf_rec->auth_timeout || !conf_rec->threshold)
    return DECLINED;

  /* abort and retry */
  if (FALSE) {
  retry:
    transaction_abort(s, txn_id);
  }

  /* transaction_start */
  if ((result = transaction_start(s, conf_rec->db_envp,
				  NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    return DECLINED;
  }

  /* read a password record */
  LOG_PRINTF(s, "mod_iprot: getting record for IP %s", remote_ip);

  if ((result = get_record(txn_id, conf_rec->iprot_db, &d,
			   server_hostname, remote_ip, r)) != 0) {
    if (result != DB_NOTFOUND) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	return DECLINED; /* I/O Error */
      }
    }
  }

  if (!get_data_strings(r, &d, &PWStr, &BlockIgnoreStr, NULL, NULL)) {
    return DECLINED;
  }

  /* Check for block or ignore on IP. */
  if (strcmp(BlockIgnoreStr, ""))
    switch (check_block_ignore(BlockIgnoreStr, server_hostname,
			       remote_ip, r)) {
    case -1:	/* error or ip ignored */
      transaction_abort(s, txn_id);
      return DECLINED;
    case 0:	/* no error or abuse, continue processing */
      break;
    case 1:	/* password cracking detected or blocked */
      transaction_commit(s, txn_id, 0);
      switch (conf_rec->hack_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (conf_rec->hack_redirect_url)
	  ap_internal_redirect(conf_rec->hack_redirect_url, r);
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
      nag = conf_rec->nag;

    ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s,
		 "mod_iprot: nag = %d notifyip = %d",
		 nag, conf_rec->notifyip);

    if ((num_hits = count_hits(r, remote_ip, (char *) sent_pw,
			       PWStr, &newFootprint,
			       conf_rec->auth_timeout,/*interval*/
			       conf_rec->compareN,
			       conf_rec->threshold, 1, conf_rec)) == -1) {
      transaction_abort(s, txn_id);
      return -1; /* error in count_hits() */
    }

    if (newFootprint && /* changed in count_hits */
	(dataStr =
	combine_data_strings(r, newFootprint, BlockIgnoreStr, NULL, NULL))) {
      if ((result =
	   store_record(txn_id, conf_rec->iprot_db,
			server_hostname, remote_ip, dataStr, r)) != 0) {
	if (result == DB_LOCK_DEADLOCK) {
	  goto retry;
	} else {
	  transaction_abort(s, txn_id);
	  return -1;
	}
      }
    }

    transaction_commit(s, txn_id, 0);

    if (num_hits >= conf_rec->threshold) {
      if (nag) {
	if (conf_rec->notifyip) {
	  send_mail(r, remote_ip, c->user, 
		    admin_email, server_hostname,
		    "iProtect Hacking notification",
		    "Password hacking attempt detected",
		    conf_rec->auth_timeout, "seconds");
	}
      }
    } /* if (num_hits >= ... */

    if (num_hits > conf_rec->threshold) {
      LOG_PRINTF(s, "mod_iprot: threshold exceeded for: %s", remote_ip); 
      if (conf_rec->external_progip != NULL) {
	ap_log_error (APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s,
		      "mod_iprot: calling external program %s",
		      conf_rec->external_progip);
	call_external(r, remote_ip, conf_rec->external_progip);
      }

      switch (conf_rec->hack_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (conf_rec->hack_redirect_url)
	  ap_internal_redirect(conf_rec->hack_redirect_url, r);
	else
	  return FORBIDDEN;
      }
    }
  } else {
    LOG_PRINTF(s, "mod_iprot: no record for IP %s, creating new record",
	       remote_ip);
    snprintf(buffer, BUFFER_LEN, "1?%s:%li", sent_pw,
	     (long) (r->request_time + conf_rec->auth_timeout/*interval*/));
    LOG_PRINTF(s, "mod_iprot: new record = %s", buffer);
    if ((dataStr =
	 combine_data_strings(r, buffer, BlockIgnoreStr, NULL, NULL)))
      if ((result =
	   store_record(txn_id, conf_rec->iprot_db,
			server_hostname, remote_ip, dataStr, r)) != 0) {
	if (result == DB_LOCK_DEADLOCK) {
	  goto retry;
	} else {
	  transaction_abort(s, txn_id);
	  return -1;
	}
      }

    transaction_commit(s, txn_id, 0);
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

  DB_TXN *txn_id;
  DBT d;
  int result;

  char *IPStr = "";
  char *failedIPStr = "";
  char *successfulIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";
  char *admin_email;
  char *remote_ip;
  long interval;
  int num_hits, nag;
  char *newFootprint = NULL;

  prot_config_rec *conf_rec =	/* get our module configuration record */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  LOG_PRINTF(s, "mod_iprot: record_access enabled_flag: %d",
	     conf_rec->enabled);

  if (!conf_rec->enabled) return OK;

  /* get the real ip, if possible, otherwise go with r->remote_ip */
  remote_ip = lookup_header(r, "HTTP_X_FORWARDED_FOR");
  if (remote_ip == NULL) remote_ip = c->remote_ip;

  /* if the user or ip is in the ignore list, just ignore it... */
  if (match_string(r, conf_rec->ignore_users, c->user)) return OK;
  if (match_string(r, conf_rec->ignore_ips, remote_ip)) return OK;

  /* allow the IProtAbuseEmail to override the server admin, if set ???*/
  if (conf_rec->abuse_email == NULL)
    admin_email = s->server_admin;
  else
    admin_email = conf_rec->abuse_email;

  /* interval for IPs is in hours */
  if (!conf_rec->access_timeout || !conf_rec->threshold)
    return DECLINED;

  interval = (conf_rec->access_timeout * 60) * 60;	 

  /* abort transaction and retry */
  if (FALSE) {
  retry:
    transaction_abort(s, txn_id);
  }

  /* transaction_start */
  if ((result = transaction_start(s, conf_rec->db_envp,
				  NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    return OK;
  }

  LOG_PRINTF(s, "mod_iprot: getting record for username %s", c->user);	

  /* read a username record */
  if ((result = get_record(txn_id, conf_rec->iprot_db, &d,
			   server_hostname, c->user, r)) != 0) {
    if (result != DB_NOTFOUND) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	return OK; /* I/O Error */
      }
    }
  }

  if (!get_data_strings(r, &d, &IPStr,
			&failedIPStr, &BlockIgnoreStr, &BWStr) ||
      (strcmp(IPStr, "") && !(successfulIPStr =
			      PSTRDUP(r->pool, IPStr)))) {
    /* count_hits() changes IPStr */
    transaction_abort(s, txn_id);
    return OK;
  }

  /* check for block or ignore on user */
  if (strcmp(BlockIgnoreStr, "")) {
    switch (check_block_ignore(BlockIgnoreStr, server_hostname, c->user, r)) {
    case -1:	/* error or user ignored */
      transaction_abort(s, txn_id);
      return DECLINED;
    case 0:	/* no error or abuse, continue processing */
      break;
    case 1:	/* password cracking detected or blocked */
      transaction_commit(s, txn_id, 0);
      switch (conf_rec->hack_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (conf_rec->hack_redirect_url)
	  ap_internal_redirect(conf_rec->hack_redirect_url, r);
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
      nag = conf_rec->nag;

    LOG_PRINTF(s, "mod_iprot: IPSTR = %s", IPStr);
    ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s,
		 "mod_iprot: nag = %d notifyuser = %d",
		 nag, conf_rec->notifyuser);

    if ((num_hits = count_hits(r, c->user, remote_ip,
			       IPStr, &newFootprint,
			       interval, conf_rec->compareN,
			       conf_rec->threshold, 1, conf_rec)) == -1) {
      transaction_abort(s, txn_id);
      return -1; /* error in count_hits() */
    }

    if (newFootprint) /* Changed in count_hits, save. */ {
      char *IPdata = NULL;
    
      if ((IPdata = combine_data_strings(r, newFootprint, failedIPStr,
					 BlockIgnoreStr, BWStr))) {
	if ((result =
	     store_record(txn_id, conf_rec->iprot_db,
			  server_hostname, c->user, IPdata, r)) != 0) {
	  if (result == DB_LOCK_DEADLOCK) {
	    goto retry;
	  } else {
	    transaction_abort(s, txn_id);
	    return -1;
	  }
	}
      }
    }

    if (num_hits >= conf_rec->threshold) {
      /* blocking threshold reached, send email */
      LOG_PRINTF(s, "mod_iprot: threshold exceeded for: %s", c->user);
      if (nag) { 
	if (conf_rec->notifyuser) {
	  send_mail(r, remote_ip, c->user, 
		    admin_email, server_hostname,
		    "iProtect Shared Access Abuse notification",
		    "Detected use of a shared password",
		    conf_rec->access_timeout, "hours");	  
	}
      }
    } /* if (num_hits >= threshold ... */

    if (num_hits > conf_rec->threshold) {
      if (conf_rec->external_proguser != NULL) {
	ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s,
		     "mod_iprot: calling external program %s",
		     conf_rec->external_proguser);
	call_external(r, c->user, conf_rec->external_proguser);
      }

      transaction_commit(s, txn_id, 0);

      switch (conf_rec->abuse_status_return) {
      case 0:
	return DONE;
      case 1:
	return FORBIDDEN;
      case 2:
	if (conf_rec->abuse_redirect_url)
	  ap_internal_redirect(conf_rec->abuse_redirect_url, r);
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
	   combine_data_strings(r, newFootprint, failedIPStr,
				BlockIgnoreStr, BWStr))) {
	/* Don't store record if IPdata is NULL as we had an error. */
	if ((result =
	     store_record(txn_id, conf_rec->iprot_db,
			  server_hostname, c->user, IPdata, r)) != 0) {
	  if (result == DB_LOCK_DEADLOCK) {
	    goto retry;
	  } else {
	    transaction_abort(s, txn_id);
	    return -1;
	  }
	}
      }
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

    if ((IPdata = combine_data_strings(r,
				       buffer,
				       failedIPStr,
				       BlockIgnoreStr,
				       BWStr))) {
      if ((result =
	   store_record(txn_id, conf_rec->iprot_db,
			server_hostname, c->user, IPdata, r)) != 0) {
	if (result == DB_LOCK_DEADLOCK) {
	  goto retry;
	} else {
	  transaction_abort(s, txn_id);
	  return -1;
	}
      }
    }
  }

  transaction_commit(s, txn_id, 0);
  return OK; 
} /* record_access_attempt */

static void record_failed_auth_attempt(request_rec *r,
				       conn_rec *c,
				       server_rec *s,
				       prot_config_rec *conf_rec,
				       const char *sent_pw,
				       const char *server_hostname)
{
  DB_TXN *txn_id;
  DBT d;
  int result;

  char *remote_ip;
  int num_hits;
  char *newFootprint = NULL;
  char *successfulIPStr = "";
  char *failedIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";

  /* get the proxy ip if one exists, otherwise go with r->remote_ip */
  remote_ip = lookup_header(r, "HTTP_X_FORWARDED_FOR");
  if (remote_ip == NULL) remote_ip = c->remote_ip;

  /* abort and retry */
  if (FALSE) {
  retry:
    transaction_abort(s, txn_id);
  }

  /* transaction_start */
  if ((result = transaction_start(s, conf_rec->db_envp,
				  NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    return;
  }

  /* Abort and return if fatal error. Caller ignores error and continues. */
  LOG_PRINTF(s, "mod_iprot: getting record for username %s", c->user);

  if ((result = get_record(txn_id, conf_rec->iprot_db, &d,
			   server_hostname, c->user, r)) != 0) {
    if (result != DB_NOTFOUND) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	return; /* I/O Error */
      }
    }
  }

  if (!get_data_strings(r, &d, &successfulIPStr,
			&failedIPStr, &BlockIgnoreStr, &BWStr)) {
    transaction_abort(s, txn_id);
    return;
  }

  if (strcmp(failedIPStr, "")) {
    int nag;

    if (index(failedIPStr, '\xbf') == NULL)  /* ¿ */
      nag = 1;
    else 
      nag = conf_rec->nag;

    /* Record found for user with failed auth attempts. */
    LOG_PRINTF(s, "mod_iprot: failedIPStr = %s", failedIPStr);

    if ((num_hits = count_hits(r, c->user, remote_ip, failedIPStr,
			       &newFootprint,
			       conf_rec->failed_timeout/*interval*/,
			       conf_rec->failed_compareN,
			       conf_rec->failed_threshold,
			       1, conf_rec)) == -1) {
      transaction_abort(s, txn_id);
      return; /* error in count_hits() */
    }

    if (newFootprint) { /* changed in count_hits */
      char *IPdata = NULL;

      if ((IPdata = combine_data_strings(r,
					 successfulIPStr,
					 newFootprint,
					 BlockIgnoreStr,
					 BWStr))) {
	if ((result =
	     store_record(txn_id, conf_rec->iprot_db,
			  ap_get_server_name(r), c->user, IPdata, r)) != 0) {
	  if (result == DB_LOCK_DEADLOCK) {
	    goto retry;
	  } else {
	    transaction_abort(s, txn_id);
	    return;
	  }
	}
      }
    }

    transaction_commit(s, txn_id, 0);

    if (num_hits >= conf_rec->failed_threshold) { 
      /* username is being abused, notify */
      const char *server_hostname = ap_get_server_name(r);
      char *admin_email;

      /* allow the IProtEmail to override the server admin, if set. Could
	 this be moved to the configuration section?? ???*/
      if (conf_rec->hack_email == NULL)
	admin_email = s->server_admin;
      else
	admin_email = conf_rec->hack_email;

      if (nag) {
	if (conf_rec->notifylogin) {
	  send_mail(r, remote_ip, c->user, 
		    admin_email, server_hostname,
		    "iProtect Failed Login notification",
		    "Too many failed logins for user detected",
		    conf_rec->failed_timeout, "seconds");
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
	     (long) (r->request_time + conf_rec->failed_timeout/*interval*/));
    LOG_PRINTF(s, "mod_iprot: new record = %s", failedIPStr);

    if ((IPdata = combine_data_strings(r,
				       successfulIPStr,
				       failedIPStr,
				       BlockIgnoreStr,
				       BWStr))) {
      if ((result =
	   store_record(txn_id, conf_rec->iprot_db,
			ap_get_server_name(r), c->user, IPdata, r)) != 0) {
	if (result == DB_LOCK_DEADLOCK) {
	  goto retry;
	} else {
	  transaction_abort(s, txn_id);
	  return;
	}
      }
    }

    transaction_commit(s, txn_id, 0);
  }
} /* record_failed_auth_attempt */

static int record_bytes_sent(request_rec *r)
{
  server_rec *s = r->server;
  conn_rec *c = r->connection;
  const char *server_hostname = ap_get_server_name(r);

  DB_TXN *txn_id;
  DBT d;
  int result;

  char *successfulIPStr = "";
  char *failedIPStr = "";
  char *BlockIgnoreStr = "";
  char *BWStr = "";

# undef BUFFER_LEN
# define BUFFER_LEN 32
  char buffer[BUFFER_LEN];
  char *dataStr = NULL;

  time_t timestamp;
  int total_bytes_sent = 0;
  char flag_char = S_CHAR;	/* separator char coding if
				   email sent for block */
				 
  /* check for user in config file ignore ??? */

  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* if the user is in the ignore list, just ignore it... */
  if (match_string(r, conf_rec->ignore_users, c->user))
    return TRUE;

  /* abort and retry */
  if (FALSE) {
  retry:
    transaction_abort(s, txn_id);
  }

  /* transaction_start */
  if ((result = transaction_start(s, conf_rec->db_envp,
				  NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    return -1;
  }

  /* get user's data record and bw str */
  if ((result = get_record(txn_id, conf_rec->iprot_db, &d,
			   server_hostname, c->user, r)) != 0) {
    if (result != DB_NOTFOUND) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	return -1; /* I/O Error */
      }
    }
  }

  if (!(get_data_strings(r, &d,
			 &successfulIPStr,
			 &failedIPStr,
			 &BlockIgnoreStr,
			 &BWStr))) {
    transaction_abort(s, txn_id);
    return FALSE; /* I/O Error */
  }

  if (strcmp(BlockIgnoreStr, "") && BlockIgnoreStr[0] == 'I') {
    transaction_abort(s, txn_id); 
    return TRUE;
  }

  /* update bw str */
  /* bytes:timestamp */
  if (strcmp(BWStr, "")) {
    if (sscanf(BWStr, "%i%c%i", &total_bytes_sent,
	       &flag_char, (int *)&timestamp) == 3) {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r,
		    "record_bytes_sent(): total_bytes_sent %i",
		    total_bytes_sent);
      total_bytes_sent += + r->bytes_sent;
#if 0
      if (!conf_rec->bw_timeout) ???
	timestamp = r->request_time; /* update timestamp if not using
					daily bw limit */
#endif
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r,
		    "record_bytes_sent(): total_bytes_sent %i, bytes_sent %li",
		    total_bytes_sent, r->bytes_sent);
    } else { 
      transaction_abort(s, txn_id);
      ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, r,
		    "sscanf() failed in record_bytes_sent()");
      return FALSE;
    }
  } else {
    total_bytes_sent = r->bytes_sent;
    timestamp = r->request_time; /* timestamp is only set when there
				    is no existing record because we
				    keep track of bytes downloaded per
				    day */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r,
		  "record_bytes_sent(): total_bytes_sent %i, bytes_sent %li",
		  total_bytes_sent, r->bytes_sent);
  }

  /* make a new bw str */
  snprintf(buffer, BUFFER_LEN, "%i%c%i",
	   total_bytes_sent, flag_char, (int)timestamp);

  /* store user's record */
  if ((dataStr =
       combine_data_strings(r,
			    successfulIPStr,
			    failedIPStr,
			    BlockIgnoreStr,
			    buffer))) {
    if ((result =
	 store_record(txn_id, conf_rec->iprot_db,
		      server_hostname, c->user, dataStr, r)) != 0) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	return FALSE;
      }
    }
  }

  transaction_commit(s, txn_id, 0);
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

  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* If authentication is not in use for this request exit. */
  if (!c->ap_auth_type) return DECLINED;

  auth_result = ap_get_basic_auth_pw(r, &sent_pw);

  switch (auth_result) {
  case OK:
    switch (r->status) {
    case HTTP_UNAUTHORIZED : { /* 401 */
      record_failed_auth_attempt(r, c, s, conf_rec,
				 sent_pw, server_hostname);
      return DECLINED; /* incorrect user or password */
    }
    case HTTP_NOT_MODIFIED: /* 304 ??? */
    case HTTP_OK: { /* 200 */
      if (conf_rec->max_bytes_user)
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
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  if (&set_threshold == cmd->info) {
    conf_rec->threshold = atoi(t);
  } else
    if (&set_auth_timeout == cmd->info) {
      conf_rec->auth_timeout = atoi(t);
    } else
      if (&set_access_timeout == cmd->info) {
	conf_rec->access_timeout = atoi(t);
      } else
	if (&set_compare == cmd->info) {
	  conf_rec->compareN = atoi(t);
	} else
	  if (&set_ignore_user == cmd->info) {
	    ap_table_setn(conf_rec->ignore_users, t, t);
	  } else
	    if (&set_ignore_ip == cmd->info) {
	      ap_table_setn(conf_rec->ignore_ips, t, t);
	    } else
	      if (&set_email == cmd->info) {
		if (!(conf_rec->email = PSTRDUP(cmd->pool, t)))
		  server_init_abort(cmd->server);
	      } else
		if (&set_abuse_email == cmd->info) {
		  if (!(conf_rec->abuse_email = PSTRDUP(cmd->pool, t)))
		    server_init_abort(cmd->server);
		} else
		  if (&set_hack_email == cmd->info) {
		    if (!(conf_rec->hack_email = PSTRDUP(cmd->pool, t)))
		      server_init_abort(cmd->server);
		  } else
		    if (&set_bw_email == cmd->info) {
		      if (!(conf_rec->bw_email = PSTRDUP(cmd->pool, t)))
			server_init_abort(cmd->server);
		    } else
		      if (&set_externalip == cmd->info) {
			if (!(conf_rec->external_progip =
			      PSTRDUP(cmd->pool, t)))
			  server_init_abort(cmd->server);  
		      } else
			if (&set_externaluser == cmd->info) {
			  if (!(conf_rec->external_proguser =
				PSTRDUP(cmd->pool, t)))
			    server_init_abort(cmd->server);
			} else
			  if (&set_failed_threshold == cmd->info) {
			    conf_rec->failed_threshold = atoi(t);	 
			  } else
			    if (&set_failed_timeout == cmd->info) {
			      conf_rec->failed_timeout = atol(t);	 
			    } else
			      if (&set_failed_compare == cmd->info) {
				conf_rec->failed_compareN = atoi(t);  
			      } else
				if (&set_abuse_redirect_url == cmd->info) {
				  if (!(conf_rec->abuse_redirect_url =
					PSTRDUP(cmd->pool, t)))
				    server_init_abort(cmd->server);
				} else
				  if (&set_hack_redirect_url == cmd->info) {
				    if (!(conf_rec->hack_redirect_url =
					  PSTRDUP(cmd->pool, t)))
				      server_init_abort(cmd->server);
				  } else
				    if (&set_file == cmd->info) {
				      if (!strstr(ap_server_root_relative(cmd->pool, t),
						  IPROT_DB_EXT)) {
					conf_rec->filename =
					  (char *)PALLOC(cmd->pool, sizeof(ap_server_root_relative(cmd->pool, t) + sizeof(IPROT_DB_EXT) + 1));
					strcpy(conf_rec->filename, ap_server_root_relative(cmd->pool, t));
					strcat(conf_rec->filename, IPROT_DB_EXT);
				      } else {
					if (!(conf_rec->filename =
					      ap_server_root_relative(cmd->pool, t)))
					  server_init_abort(cmd->server);
				      }
				    } else
				      if (&set_block_ignore_file == cmd->info) {
					if (!strstr(ap_server_root_relative(cmd->pool, t),
						    IPROT_DB_EXT)) {
					  conf_rec->block_ignore_filename =
					    (char *)PALLOC(cmd->pool, sizeof(ap_server_root_relative(cmd->pool, t) + sizeof(IPROT_DB_EXT) + 1));
					  strcpy(conf_rec->block_ignore_filename, ap_server_root_relative(cmd->pool, t));
					  strcat(conf_rec->block_ignore_filename, IPROT_DB_EXT);
					} else {
					  if (!(conf_rec->block_ignore_filename =
						ap_server_root_relative(cmd->pool, t)))
					    server_init_abort(cmd->server);
					}
				      } else
					if (&set_max_bytes_user == cmd->info) {
					  conf_rec->max_bytes_user = atoi(t);
					} else
					  if (&set_bw_redirect_url ==
					      cmd->info) {
					    if (!(conf_rec->bw_redirect_url =
						  PSTRDUP(cmd->pool, t)))
					      server_init_abort(cmd->server);
					  }
  return NULL;
} /* set_var */

static const char *set_nag(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->nag = val;
  return NULL;
}

static const char *set_enabled(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->enabled = val;
  return NULL;
}

static const char *set_notifyip(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->notifyip= val;
  return NULL;
}

static const char *set_notifybw(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->notifybw= val;
  return NULL;
}

static const char *set_notifyuser(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->notifyuser = val;
  return NULL;
}

static const char *set_notifylogin(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->notifylogin = val;
  return NULL;
}

static const char *set_abuse_status_return(cmd_parms *cmd,
					   void *dummy,
					   const char *val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->abuse_status_return = atoi(val);
  return NULL;
}

static const char *set_hack_status_return(cmd_parms *cmd,
					  void *dummy,
					  const char *val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->hack_status_return = atoi(val);
  return NULL;
}

static const char *set_bw_status_return(cmd_parms *cmd,
					void *dummy,
					const char *val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->bw_status_return = atoi(val);
  return NULL;
}

static const char *set_bw_timeout(cmd_parms *cmd,
				  void *dummy,
				  const char *val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->bw_timeout = atoi(val);
  return NULL;
}

static const char *set_no_HEAD_req(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->no_HEAD_req = val;
  return NULL;
}

static const char *set_all_hosts_admin(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *conf_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config,
					  &iprot_module);
  conf_rec->all_hosts_admin = val;
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
  mod_init,		/* module initializer			     */
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
  child_init,		/* process initialization child_init	     */
  child_exit,		/* process exit/cleanup child_exit	     */
#if DEBUG
  post_read_request	/* [1]	post read-request		     */
#else
  NULL,			/* [1]	post read-request		     */
#endif
};

/*
 * record_auth_attempt() multiple login attempts from one IP.
 * record_access_attempt() multiple IP addresses with one username.
 *  
 * Failed password attempts are recorded in iprot_record().
 * record_failed_auth_attempt()
 */
