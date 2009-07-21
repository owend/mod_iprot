#include <db.h>
#include <db1/ndbm.h>

int main (int argc, char **argv)
{
  DBM *db;
  datum k,v;
  char *filename;
  char key[128], val[1024];

  if (argc == 1)
  {
     printf ("usage: dump <filename>\n");
     exit(0);
  }
  else
  {
     filename = argv[1];
  }

  if (!(db = dbm_open(filename, DB_RDONLY, 0664))) {
    printf("could not open dbm file: %s\n", filename);
    exit(1);
  }

  k = dbm_firstkey (db);
 
  while (k.dptr != NULL) 
  {
     v = dbm_fetch (db, k);
     strncpy (key, k.dptr, k.dsize);  key[k.dsize] = '\0';
     strncpy (val, v.dptr, v.dsize);  val[v.dsize] = '\0';
      
     printf ("key= %s val=%s\n", key, val); 

     memset (key, 0, k.dsize +1);
     memset (val, 0, v.dsize +1);
     k = dbm_nextkey (db);
  }

  return 0; 
}
