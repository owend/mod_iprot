
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <gdbm.h>

#define IPROT_DB_FLAGS GDBM_WRCREAT | GDBM_SYNC

/*
 * Module definition information - the part between the -START and -END
 * lines below is used by Configure.
 *
 * MODULE-DEFINITION-START
 * Name: iprot_module
 * ConfigStart
    . ./helpers/find-dbm-lib
 * ConfigEnd
 * MODULE-DEFINITION-END
 */

/*  ARGH!  Changed interfaces between apache releases */

#if APACHE_RELEASE >= 1030000
  #define LOG_ERROR(CONF, FMT, VAR) (ap_log_error(APLOG_MARK, APLOG_WARNING, CONF, FMT, VAR))
  #define LOG_PRINTF(CONF, FMT, VAR) (ap_log_error(APLOG_MARK, APLOG_INFO, CONF, FMT, VAR))
  #define PALLOC ap_palloc
  #define GET_MODULE_CONFIG ap_get_module_config
  #define PSTRDUP ap_pstrdup
  module MODULE_VAR_EXPORT iprot_module;

#else
  #define LOG_ERROR(CONF, FMT, VAR) (log_error(FMT, CONF))
  #define LOG_PRINTF(CONF, FMT, VAR) (log_error(FMT, CONF))
  #define PALLOC palloc
  #define GET_MODULE_CONFIG get_module_config
  #define PSTRDUP pstrdup
  module iprot_module;
#endif

/* structure holding info from config files */

typedef struct {
  char *threshold;
  char *auth_timeout;
  char *access_timeout;
  char *filename;
  char *compareN;
  char *email;
  char *external_progip;
  char *external_proguser;
  int nag;
  int enabled;
  int notify;
  table *ignore_users;
  table *ignore_ips;
} prot_config_rec;

typedef struct {
  char item[128];
  long timestamp;
} footprint;

/* function to initialize config structure */
static void *create_prot_config(pool *p, server_rec *s)
{
  prot_config_rec *rec = (prot_config_rec *) PALLOC (p, sizeof(prot_config_rec));

  LOG_PRINTF (s, "initializing %s", "mod_iprot");

  rec->threshold = NULL; 	    /* num hits */
  rec->auth_timeout = NULL; 	    /* timeout for authorizations */
  rec->access_timeout = NULL; 	    /* timeout for accesses */

  rec->filename = NULL;
  rec->compareN = NULL;
  rec->external_progip = NULL;
  rec->external_proguser = NULL;
  rec->email = NULL;
  rec->nag = 0;
  rec->notify = 1;  // send mail by default
  rec->enabled = 1;  // enabled by default
  rec->ignore_users = ap_make_table(p, 20);
  rec->ignore_ips = ap_make_table(p, 20);
  return rec;
}

static void *merge_prot_config(pool *p, void *basev, void *newv)
{
  prot_config_rec *base, *new;

  base = (prot_config_rec *)basev;
  new = (prot_config_rec *)newv;
  
  new->threshold = new->threshold != NULL ? new->threshold : base->threshold;
  new->auth_timeout = new->auth_timeout != NULL ? new->auth_timeout : base->auth_timeout;
  new->access_timeout = new->access_timeout != NULL ? new->access_timeout : base->access_timeout;
  new->filename = new->filename != NULL ? new->filename : base->filename;
  new->compareN = new->compareN != NULL ? new->compareN : base->compareN;
  new->email = new->email != NULL ? new->email : base->email;
  new->external_progip = new->external_progip != NULL ? new->external_progip : base->external_progip;
  new->external_proguser = new->external_proguser != NULL ? new->external_proguser : base->external_proguser;
  new->nag = new->nag;
  new->enabled = new->enabled;
  new->notify = new->notify;

  return (void *)new;
}

static void send_mail (char *ip, long timestamp, char *user, char *admin, char *host, char *message)
{

  char temp[255];  FILE *pi;
  /* Open e-mail command.  Must be in path. */

  sprintf(temp, "sendmail %s", (const char*) admin);
  
  pi = popen(temp, "w");
  
  if (pi == NULL) return;

  /* Dump header: */

  fprintf(pi, "Subject: IProt notification [%s]\n", user);
  /* end of headers */

  fprintf(pi, "\n");

  /* Dump message: */
  fprintf (pi, "%s, denying further access.\n\n", message);
  fprintf (pi, "user: %s\n", user);
  fprintf (pi, "timestamp: %s", ctime(&timestamp));
  fprintf (pi, "browser ip: %s\n", ip);
  fprintf (pi, "server hostname: %s\n", host); 

  pclose(pi);

}

static void call_external (char *ip, char *cmd)
{
  char temp[255]; FILE *pi;
  
  /* open external cmd. Must be in path, or full path specified. */
  
  sprintf (temp, (const char *)cmd, (const char*) ip);

  pi = popen (temp, "w");

  if (pi == NULL)  return;  /* print an error */

  pclose (pi);

}

/* return true if user string found in any table entry, where each table 
   entry is a string used for a regex */

static int match_string (request_rec *r, table *t, char *str)
{
  regex_t *regex;
  int i, match;
  server_rec *s = r->server;
  array_header *arr = ap_table_elts(t);
  table_entry *elts = (table_entry *) arr->elts;

  for (i=0; i < arr->nelts; ++i)
  {
    regex = ap_pregcomp(r->pool, elts[i].key, REG_EXTENDED | REG_NOSUB);
    match = ap_regexec (regex, str, 0, NULL, 0);
    /*ap_log_error (APLOG_MARK, APLOG_INFO, s, "matching %s against %s returns %d", elts[i].key, str, match); */
    /* if match == 0, we have a winner */
    ap_pregfree (r->pool, regex);
    if (match == 0) return 1;
  }
  return 0;
}

static int get_footprint_list (char *footprintStr, footprint *footprint_list, long request_time, server_rec *s)
{
  int i = 0, count = 0;
  char item[128];
  long timestamp;
  int num_ips = 0;

  num_ips = atoi(strtok (footprintStr, "?\xbf")); /* ? and inverted? */
  
  for (i = 0; i < num_ips; i++)
  {
	strcpy (item, strtok(NULL, ":"));
    	timestamp = atol(strtok(NULL, ";"));

	if (timestamp > request_time && (item != NULL))
	{
	  strcpy (footprint_list[count].item, item);
	  footprint_list[count].timestamp = timestamp;
	  count ++;
	}
  }
  return count;
}

void new_str_from_datum (datum d, char **str, request_rec *r)
{
   *str = PALLOC (r->pool, d.dsize +1);
   strncpy (*str, d.dptr, d.dsize);
   free (d.dptr);
   (*str)[d.dsize] = '\0';
}

void get_record (GDBM_FILE db, datum *d, char *host, char *key, request_rec *r)
{
   datum k;
   k.dsize = strlen(key) + strlen(host);
   k.dptr = PALLOC (r->pool, k.dsize +1);
   strcpy (k.dptr, key);
   strcat (k.dptr + strlen(key), host);

   *d = gdbm_fetch (db, k);   
}

void store_record (GDBM_FILE db, char *host, char *key, char *value, request_rec *r)
{
  datum k, v;

  k.dsize = strlen (key) + strlen(host);
  k.dptr = PALLOC (r->pool, k.dsize +1);
  strcpy (k.dptr, key);
  strcat (k.dptr + strlen (key), host);
  v.dsize = strlen (value);
  v.dptr = PALLOC(r->pool, v.dsize +1);
  strcpy (v.dptr, value);
  gdbm_store (db, k, v, GDBM_REPLACE);

}

int count_hits (GDBM_FILE db, char *key, char *item, char *footprintStr, prot_config_rec * conf, request_rec *r, int interval)
{

  footprint *footprint_list;
  char buffer [128];
  char *ques_ptr;
  int i, j, chars_to_count, item_match;
  int compareN = atoi(conf->compareN);
  char *newFootprint = PALLOC (r->pool, 20 + strlen(item) + strlen(footprintStr));
  int num_items = atoi(footprintStr);  /* stops at first non numeric */
  int threshold = atoi(conf->threshold);
  conn_rec *c = r->connection;
  server_rec *s = r->server;
  char ques_char = '?';

  if (index (footprintStr, '\xbf') != NULL)
    ques_char = '\xbf'; /* preseve the ques_char even if list pruned to 0 */
  
  footprint_list = PALLOC (r->pool, sizeof (footprint) * (num_items + 1));
  num_items = get_footprint_list (footprintStr, footprint_list, (long) r->request_time, s);

  /* if we're over the threshold after prune, don't bother continuing */
  if (num_items > threshold)
  {
    ap_log_error(APLOG_MARK, APLOG_INFO, s, "mod_iprot: count %d exceeds threshold %d, blocking immediately.", num_items, threshold);
    return num_items;  /* bad user */
  }
  
  /* start a new footprintStr for building as we go */
  sprintf (newFootprint, "%d%c", num_items +1, ques_char);
  
  for (i = 0; i < num_items ; i++)
  {
	item_match = 1;
	chars_to_count = 0;
	/* first check if this item is a name or an IP */
	if (index (item, '.') == NULL)
	{
	  /* it's a name, compare the whole thing */
	  item_match = strcmp (footprint_list[i].item, item);
	}
	else
	{
	  /* it's an IP, only compare the first N chunks */
	  for (j=0; j < compareN; j++)
	  {
		chars_to_count = chars_to_count + 1 + strcspn (item+chars_to_count, ".");
	  }
	  item_match = strncmp (footprint_list[i].item, item, chars_to_count);
	}
	
	/* if this item exists, abort further processing and return OK*/
	if (item_match == 0) 
	{
	  LOG_PRINTF(s, "mod_iprot: item %s found in list, returning OK", item);
	  return 0; /* ok user */
	}
	/* else put this IP back on the string */
	else
	{
	  sprintf (buffer, "%s:%ld;", footprint_list[i].item, footprint_list[i].timestamp);
	  strcat (newFootprint, buffer);
	}
  }
  
/* if we got this far, then the ip address doen't exist, add to the list with new timestamp */
  sprintf (buffer, "%s:%ld", item, (long) (r->request_time + interval));
  strcat (newFootprint, buffer);

  /* it's a bounce.  set the no-nag flag */
  if (num_items == threshold)
  {
    ques_ptr = strchr (newFootprint, '?');
    if (ques_ptr != NULL)
      *ques_ptr = '\xbf'; 
  }

  LOG_PRINTF (s, "mod_iprot: item %s was not found on list", item);
  LOG_PRINTF (s, "mod_iprot: new record value = %s", newFootprint);
  store_record (db, s->server_hostname, key, newFootprint, r);
    
  return num_items;
}

/* basic auth step, watch for multiple login attempts from one ip */
static int record_auth_attempt (request_rec *r)
{
  GDBM_FILE db;
  datum d;
  char *PWStr;
  const char *sent_pw;
  char *admin_email;
  char buffer[128];
  int res, num_hits, threshold, nag;
  long interval;
  conn_rec *c = r->connection;
  server_rec *s = r->server;

  prot_config_rec *rec = (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* if basic auth hasn't triggered yet, prompt for password */
  if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
    return res;

  /* defensive programming */
  if (strlen (sent_pw) == 0) return DECLINED;
  if (strlen (c->user) == 0) return DECLINED;

  LOG_PRINTF (s, "mod_iprot: enabled_flag = %d", rec->enabled);

  if (! rec->enabled)  /* enable flag is not set */
  {
    return DECLINED;
  }

  /* if the user is in the ignore list, just ignore it... */
  if (match_string (r, rec->ignore_users, c->user))
  {
    return DECLINED;
  }
  /* if the ip is in the ignore list, just ignore it... */
  if (match_string (r, rec->ignore_ips, c->remote_ip))
  {
    return DECLINED;
  }

  /* allow the IProtEmail to override the server admin, if set */
  if (rec->email == NULL)
    admin_email = s->server_admin;
  else
    admin_email = rec->email;

  /* interval for login attempts is in seconds, not hours */
  if (rec->auth_timeout == NULL || rec->threshold == NULL) return DECLINED;

  interval = atol (rec->auth_timeout);  
  threshold = atoi (rec->threshold);

  /* read a password record */

  if (!(db = gdbm_open(rec->filename, 0, IPROT_DB_FLAGS, 0664, NULL))) {
    LOG_ERROR(s, "could not open dbm file: %s", rec->filename);
    return DECLINED;
  }

  LOG_PRINTF(s, "mod_iprot: getting record for IP %s", c->remote_ip);
  get_record (db, &d, s->server_hostname, c->remote_ip, r);
  
  if (d.dptr)
  {
    new_str_from_datum (d, &PWStr, r);
    LOG_PRINTF (s, "mod_iprot: PWSTR = %s", PWStr);

    /* if db record indicates no mail has yet been sent for this entry,
       then send something. otherwise, obey the config file */
    if (index(PWStr, '\xbf') == NULL) 
      nag = 1;
    else 
      nag = rec->nag;

    ap_log_error (APLOG_MARK, APLOG_INFO, s, "mod_iprot: nag = %d notify = %d", nag, rec->notify);

    num_hits = count_hits (db, c->remote_ip, (char*) sent_pw, PWStr, rec, r, interval);
    gdbm_close(db);

    ap_log_error (APLOG_MARK, APLOG_INFO, s, "num_hits = %d", num_hits);
    if (num_hits >= threshold)
    {
      if (num_hits == threshold)
      { 
		LOG_PRINTF (s, "mod_iprot: threshold exceeded for: %s", c->remote_ip); 
		if (nag)
		{
		  if (rec->notify)
                  {
		    ap_log_error (APLOG_MARK, APLOG_INFO, s, "mod_iprot: sending email to %s", admin_email);
		    send_mail (c->remote_ip, (long) r->request_time, c->user, 
					 admin_email, s->server_hostname,
					 "Password hacking attempt detected");
                  }
 		  if (rec->external_progip != NULL)
                  {
		    ap_log_error (APLOG_MARK, APLOG_INFO, s, "mod_iprot: calling external program %s", rec->external_progip);
		    call_external(c->remote_ip, rec->external_progip);
                  }
		}
      }
      return FORBIDDEN;
    }
  }
  else
  {
    LOG_PRINTF (s, "mod_iprot: no record for IP %s, creating new record", c->remote_ip);      
    sprintf (buffer, "1?%s:%ld", sent_pw, (long) (r->request_time + interval));
    LOG_PRINTF (s, "mod_iprot: new record = %s", buffer);
    store_record (db, s->server_hostname, c->remote_ip, buffer, r);
    gdbm_close (db); 
  }
  
  return DECLINED;
}

// passed basic auth, now we watch for multiple ip addresses with one username
static int record_access_attempt (request_rec *r)
{
  GDBM_FILE db;
  datum d;
  char *IPStr;
  char *admin_email;
  char buffer[128];
  conn_rec *c = r->connection;
  server_rec *s = r->server;
  long interval;
  int num_hits, threshold, nag;

  /* get our configuration record */
  prot_config_rec *rec = (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  LOG_PRINTF (s, "mod_iprot: record_access_attempt %s", "");
  LOG_PRINTF (s, "mod_iprot: enabled_flag: %d", rec->enabled);

  if (! rec->enabled)
  {
    return OK;
  }

  /* if the user or ip is in the ignore list, just ignore it... */
  if (match_string (r, rec->ignore_users, c->user))
  {
    return OK;
  }
  if (match_string (r, rec->ignore_ips, c->remote_ip))
  {
    return OK;
  }

  /* allow the IProtEmail to override the server admin, if set */
  if (rec->email == NULL)
	admin_email = s->server_admin;
  else
	admin_email = rec->email;

  /* interval for IPs is in hours */
  if (rec->access_timeout == NULL || rec->threshold == NULL) return DECLINED;

  interval = atol (rec->access_timeout) * 60 * 60;  
  threshold = atoi (rec->threshold);

  /* read a username record */

  if (!(db = gdbm_open(rec->filename, 0, IPROT_DB_FLAGS, 0664, NULL))) {
    LOG_ERROR(s, "could not open dbm file: %s", rec->filename);
    return OK;
  }

  LOG_PRINTF (s, "mod_iprot: getting record for username %s", c->user);  
  get_record (db, &d, s->server_hostname, c->user, r);
  if (d.dptr)
  {
    new_str_from_datum (d, &IPStr, r);

    /* if db record indicates no mail has yet been sent for this entry,
       then send something. otherwise, obey the config file */
    if (index(IPStr, '\xbf') == NULL) 
      nag = 1;
    else 
      nag = rec->nag;

    LOG_PRINTF (s, "mod_iprot: IPSTR = %s", IPStr);
    ap_log_error (APLOG_MARK, APLOG_INFO, s, "mod_iprot: nag = %d notify = %d", nag, rec->notify);

    num_hits = count_hits (db, c->user, c->remote_ip, IPStr, rec, r, interval);
    gdbm_close(db);

    if (num_hits >= threshold)
    {
      if (num_hits == threshold)
      {
	LOG_PRINTF (s, "mod_iprot: threshold exceeded for: %s", c->user);
	if (nag)
	{ 
          if (rec->notify)
	  {
	    ap_log_error (APLOG_MARK, APLOG_INFO, s, "mod_iprot: sending email to %s", admin_email);
	    send_mail (c->remote_ip, (long) r->request_time, c->user, 
		     admin_email, s->server_hostname,
		     "Detected use of a stolen password");	  
	  }
 	  if (rec->external_proguser != NULL)
          {
	    ap_log_error (APLOG_MARK, APLOG_INFO, s, "mod_iprot: calling external program %s", rec->external_proguser);
	    call_external(c->user, rec->external_proguser);
          }
	}
      }
      return FORBIDDEN;
    }
  }
  else  /* no record found in db for that user, add a new record */
  {
    LOG_PRINTF (s, "mod_iprot: no record for username %s detected, creating new record", c->user);
    sprintf (buffer, "1?%s:%ld", c->remote_ip, (long) (r->request_time + interval));
    LOG_PRINTF (s, "mod_iprot: new record = %s", buffer);
    store_record (db, s->server_hostname, c->user, buffer, r);
    gdbm_close(db);
  }

  return OK; 
}

/* static addresses that we can use in a switch type statement to figure
   out which "set" function has been called... */

static int set_threshold,set_auth_timeout, set_access_timeout,set_file,set_compare,set_ignore_ip,set_ignore_user,set_email,set_externalip, set_externaluser;

static const char *set_var (cmd_parms *cmd, void *dummy, char *t)
{
  prot_config_rec *r = (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config, &iprot_module);
  
  if (&set_threshold == cmd->info)
  {
    r->threshold = PSTRDUP(cmd->pool, t);    
  }
  else if (&set_auth_timeout == cmd->info)
  {
    r->auth_timeout = PSTRDUP(cmd->pool, t);
  }
  else if (&set_access_timeout == cmd->info)
  {
    r->access_timeout = PSTRDUP(cmd->pool, t);
  }
  else if (&set_file == cmd->info)
  {
    r->filename = PSTRDUP(cmd->pool, t);
  }
  else if (&set_compare == cmd->info)
  {
    r->compareN = PSTRDUP(cmd->pool, t);
  }
  else if (&set_ignore_user == cmd->info)
  {
    ap_table_setn(r->ignore_users, t, t);
  }
  else if (&set_ignore_ip == cmd->info)
  {
    ap_table_setn(r->ignore_ips, t, t);
  }
  else if (&set_email == cmd->info)
  {
    r->email = PSTRDUP(cmd->pool, t);
  }
  else if (&set_externalip == cmd->info)
  {
    r->external_progip = PSTRDUP (cmd->pool, t);
  }
  else if (&set_externaluser == cmd->info)
  {
    r->external_proguser = PSTRDUP (cmd->pool, t);
  }
  return NULL;
}

static const char *set_nag(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *r = (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config, &iprot_module);
  r->nag = val;
  return NULL;
}

static const char *set_enabled(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *r = (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config, &iprot_module);
  r->enabled = val;
  return NULL;
}

static const char *set_notify(cmd_parms *cmd, void *dummy, int val)
{
  prot_config_rec *r = (prot_config_rec *) GET_MODULE_CONFIG(cmd->server->module_config, &iprot_module);
  r->notify= val;
  return NULL;
}


/* table of configuration variables */
static const command_rec prot_cmds[] =
{
  // {"IProtThreshold", prot_set_threshold, NULL, RSRC_CONF, TAKE1, "integer number of ips to allow for each user"},  // old style

  {"IProtThreshold", set_var, &set_threshold, RSRC_CONF, TAKE1, "integer number of ips to allow for each user"},
  {"IProtAuthTimeout", set_var, &set_auth_timeout, RSRC_CONF, TAKE1, "number of hours to keep records of user access"},
  {"IProtAccessTimeout", set_var, &set_access_timeout, RSRC_CONF, TAKE1, "number of hours to keep records of user access"},
  {"IProtDBFile", set_var, &set_file, RSRC_CONF, TAKE1, "db file to store access data"},
  {"IProtCompareN", set_var, &set_compare, RSRC_CONF, TAKE1, "number of characters in IP addr to compare"},
  {"IProtEmail", set_var, &set_email, RSRC_CONF, TAKE1, "email address to send notifications"},
  {"IProtExternalIP", set_var, &set_externalip, RSRC_CONF, TAKE1, "external program to execute in addition to sendmail. passes in ip."},
  {"IProtExternalUser", set_var, &set_externaluser, RSRC_CONF, TAKE1, "external program to execute in addition to sendmail. passes in username."},
  {"IProtIgnoreUser", set_var, &set_ignore_user, RSRC_CONF, ITERATE, "list of user names to ignore"},
  {"IprotIgnoreIP", set_var, &set_ignore_ip, RSRC_CONF, ITERATE, "list of IP addresses to ignore."},
  {"IProtEnable", set_enabled, NULL, RSRC_CONF, FLAG, "if set off, disable checking for this virtual host. default is enabled."},
  {"IProtNag", set_nag, NULL, RSRC_CONF, FLAG, "if set, send email every time a user trips the detector, otherwise just send one mail ever"},  
  {"IProtNotify", set_notify, NULL, RSRC_CONF, FLAG, "if set, send email when a user trips the detector, otherwise just block them"},  
  {NULL}
};

#if APACHE_RELEASE >= 1030000
  module MODULE_VAR_EXPORT iprot_module =
#else
  module iprot_module =
#endif

{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    NULL,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    create_prot_config,	/* server config */
    merge_prot_config,  /* merge server config -- virtual host stuff */
    prot_cmds,		/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    record_auth_attempt,	/* check_user_id */
    record_access_attempt,	/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
#if APACHE_RELEASE >= 1030000
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
#endif
};


