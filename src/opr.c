/****************************************************************************

                      opr - Oracle Password Repository

              Copyright (C) 2000-2013 Jan-Marten Spit
                       (jmspit@euronet.nl)

       This program is free software; you can redistribute it and/or
       modify it under the terms of the GNU General Public License
       as published by the Free Software Foundation; either version 2
       of the License, or (at your option) any later version.

       This program is distributed in the hope that it will be useful,
       but WITHOUT ANY WARRANTY; without even the implied warranty of
       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
       GNU General Public License for more details.

       You should have received a copy of the GNU General Public License
       along with this program; if not, write to the Free Software
       Foundation, Inc., 59 Temple Place - Suite 330, Boston,
       MA  02111-1307, USA.

****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <termios.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif
#include "oprora.h"

/*
 * START CONFIGURABLE SECTION
 */
 
/* maximum number of entries allowed in the password repository */
#define MAX_ENTRIES 4096

char* MSG_SECURITY="sorry :("; 

/* name of the environment variable */
#define OPRREPOS "OPRREPOS"

/*
 * END CONFIGURABLE SECTION
 */
 
/* MAGIC is used to do a (simple) check on the repository file */
#define MAGIC "OraclePasswordRepository 1.1.0 "
#define W_MAGIC  32

/* maximum length of the pathname to the repository file (Practical value) */
#define W_REPOSNAME 256

/* maximum length of the pathname to the log file (Practical Value) */
#define W_LOGFILE 256 

/* length of a datime entry in the logfile (see man ctime)*/
#define W_DATETIME 26

/* maximum length of a database name (TNS Name length max hard to find in the
   Oracle manuals, so a pratical value is chosen. You can increase if needed */
#define W_DATABASE 64

/* maximum length of a schemaname (Oracle defined max) */
#define W_SCHEMANAME 30

/* maximum length of a password (Oracle defined max) */
#define W_PASSWORD 30 

/* maximum length of an OSusername (Practical value)*/
#define W_OSUSERNAME 32
 
/* size of int to string conversion buffers */
#define W_INTBUF 32 

/* number of nanoseconds to wait before lock retry */
#define LOCK_SLEEP 40000000

/* number of lock retries before giving up */
#define LOCK_RETRIES 100

/****************************************************************************
the repository header.
   magic      - this field is used to validate the file as being a repository.
   reposowner - holds the osusername of the repository creator.
   logfile    - name of the logfile. if logging not enabled, empty string.
   entries    - holds the number of entries in the repository.
****************************************************************************/
typedef struct {
  char   magic[W_MAGIC];
  char   reposowner[W_OSUSERNAME];
  char   logfile[W_LOGFILE];
  int    entries;
} Header;

/****************************************************************************
a repository entry :
  database   - the name of the database
  schemaname - the name of the schema
  osusername - the name of the osuser allowed to read the password
  password   - the password for schemaname@database
****************************************************************************/
typedef struct {
  char database[W_DATABASE];
  char schemaname[W_SCHEMANAME];
  char osusername[W_OSUSERNAME];
  char password[W_PASSWORD];
} Entry;

/****************************************************************************
global variables
****************************************************************************/
char   reposname[W_REPOSNAME];
char   osusername[W_OSUSERNAME];
Header header;
Entry  entries[MAX_ENTRIES];
static struct termios stored_settings;


/****************************************************************************
  purpose: disable character echo on the user's terminal
****************************************************************************/
void noecho()
{
  struct termios new_settings;
  tcgetattr( 0, &stored_settings );
  new_settings = stored_settings;
  new_settings.c_lflag &= (~ECHO);
  tcsetattr( 0, TCSANOW, &new_settings );
  return;
}

/****************************************************************************
  purpose: enable character echo on the users terminal
  pre    : a call to noecho must be done before calling echo, the
           terminal will be screwed up otherwise (set to uninitialized
           terminal settings)
****************************************************************************/
void echo()
{
  tcsetattr( 0, TCSANOW, &stored_settings );
  return;
}

/****************************************************************************
  purpose: convert string to uppercase (no standard function)
  pre    :
****************************************************************************/
void strtoupper( char *s )
{
  int i;
  for ( i = 0; s[i] != '\0'; i++ ) {
    s[i] = toupper( s[i] );
  }
}

/****************************************************************************
  purpose: convert string to lowercase
  pre    :
****************************************************************************/
void strtolower( char *s )
{
  int i;
  for ( i = 0; s[i] != '\0'; i++ ) {
    s[i] = tolower( s[i] );
  }
}

/****************************************************************************
  purpose: terminate in a controlled manner
  pre    :
****************************************************************************/
void terminate()
{
  unloadOraLibs();
  exit( 1 );
}

/****************************************************************************
  purpose: encrypt the entry. only the password is encrypted. calling crypt
           on an encrypted entry decrypts the entry. Note that encryption is
           too strong a word for the algorithm :), the entry is just made
           unreadable for the prowling eye. Do not rely on the encryption for
           your password's safety, rely on the UNIX access rights on the
           repository file.
  pre    : 
****************************************************************************/
void cryptEntry( entry )
Entry *entry;
{
  int seed, r, c, i;
  seed = 0;
  for ( i = 0; i < W_DATABASE; i++ )
    seed += entry->database[i];
  for ( i = 0; i < W_SCHEMANAME; i++ )
    seed += entry->schemaname[i];
  for ( i = 0; i < W_OSUSERNAME; i++ )
    seed += entry->osusername[i];
  srand( seed );
  for ( i = 0; i < W_PASSWORD; i++ )
  {
    r = rand();
    c = (char) r;
    entry->password[i] = entry->password[i] ^ c;
  }
  return;
}

/****************************************************************************
  purpose: write a message to the log
  pre    : readRepos 
****************************************************************************/
void logLine ( error, message )
int  error;
char *message;
{
  if ( strlen( header.logfile ) > 0 )
  {
    FILE *file = fopen( header.logfile , "a" );
    if ( file )
    {
       int i;
       time_t now = time( 0 );
       char buffer[W_DATETIME];
       ctime_r( &now, buffer, sizeof( buffer )  );       
       for ( i = 0; i < W_DATETIME; i++ )
         if ( buffer[i] == '\n' )
         {
           buffer[i] = 0;
           break;
         }
       if ( error )
       {
         fprintf( file,
                  "%s [fail] %s : %s\n",
                  buffer,
                  osusername,
                  message);
       } else
       {
         fprintf( file,
                  "%s [ ok ] %s : %s\n",
                  buffer,
                  osusername,
                  message);
       }
       fclose( file );
    } else
    {
      fprintf( stderr, "unable to append to logfile %s.\n", header.logfile );
      exit(-1);
    }
  } 
}

/***************************************************************************
  purpose: write a message to the logfile, if a logfile is specified.
           if error is not 0, the line contains the word 'ERROR'.
  pre    : readRepos
****************************************************************************/
void logEntryLine( error,
                   database,
                   schemaname,
                   osuser,
                   message )
int  error;
char *database;
char *schemaname;
char *osuser;
char *message;
{
  if ( strlen( header.logfile ) > 0 )
  {
    FILE *file = fopen(header.logfile,"a");
    if ( file )
    {
       int i;
       time_t now = time( 0 );
       char buffer[W_DATETIME];
       ctime_r( &now, buffer, sizeof( buffer ) );
       for ( i = 0; i < W_DATETIME; i++ )
         if ( buffer[i] == '\n' )
         {
           buffer[i] = 0;
           break;
         }
       if ( error )
       {
         fprintf( file,
                  "%s [fail] %s : (%s, %s) : %s\n",
                  buffer,
                  osuser,
                  database,
                  schemaname,
                  message);
       } else
       {
         fprintf( file,
                  "%s [ ok ] %s : (%s, %s) : %s\n",
                  buffer,
                  osuser,
                  database,
                  schemaname,
                  message);
       }
       fclose( file );
    } else
    {
      fprintf( stderr, "unable to open logfile %s.", header.logfile);
      exit(-1);
    }
  }
}


/****************************************************************************
  purpose: check if the osuser is the reposowner. if not, exit program.
  pre    : osUserName has been called, global osusername initialized and
           readRepos has been called, so header is initialized.
****************************************************************************/
void isReposOwner()
{
  if ( strncmp( osusername, header.reposowner, W_OSUSERNAME ) != 0 )
  {
     logLine( 1,
              "security (not reposowner).");
     fprintf( stderr, "%s\n", MSG_SECURITY );
     exit(-1);
  }
}

/****************************************************************************
  purpose: compare two entries. sorted on database, schemaname,
           osusername. comparison is case sensitive. this fucntion
           is used by and passed to the standard qsort call.
  pre    : p1 and p2 point to valid entries.
  post   : returns true when entries are equal. equality is reached
           when the database name, the schamename and the osusername
           are equal.
****************************************************************************/
int compareEntries( p1, p2 )
void *p1;
void *p2;
{
  int result = strncmp( ((Entry*)p1)->database,
                        ((Entry*)p2)->database,
                        W_DATABASE );
  if ( !result )
  {
    result = strncmp( ((Entry*)p1)->schemaname,
                      ((Entry*)p2)->schemaname,
                      W_SCHEMANAME );
    if ( !result )
    {
      result = strncmp( ((Entry*)p1)->osusername,
                        ((Entry*)p2)->osusername,
                        W_OSUSERNAME );
    }
  }
  return result;
}

/****************************************************************************
  purpose: sort entries. use the standard quicksort function and
           use the compareEntries function to compare.
  pre    : header and entries are initialized by readRepos.
  post   : entries are sorted using compareEntries criteria.
****************************************************************************/
void qsortEntries()
{
  qsort( entries, header.entries, sizeof(Entry), compareEntries );
}

/****************************************************************************
  purpose: read the repos header from a file. all fields are stored as
           strings thereby making the repository platform independent.
  pre    : file is a FILE* to the repository opened for reading
****************************************************************************/
int readHeader( file )
FILE *file;
{
  int i;
  char intbuf[W_INTBUF];
  for ( i = 0; i < sizeof( header.magic ); i++) 
    header.magic[i] = fgetc( file );
  for ( i = 0; i < sizeof( header.reposowner ); i++) 
    header.reposowner[i] = fgetc( file );
  for ( i = 0; i < sizeof( header.logfile ); i++) 
    header.logfile[i] = fgetc( file );    
  for ( i = 0; i < sizeof( intbuf ); i++) 
    intbuf[i] = fgetc( file );        
  if ( strlen( intbuf ) > 0 )
    header.entries = atol( intbuf );
  else 
    header.entries = 0;    
  return !ferror( file );        

}

/****************************************************************************
  purpose: write the repos header to a file. all fields are stored as strings
           making the repository platform indepenent.
  pre    : file is a FILE* to the repository opened for writing
  post   :
****************************************************************************/
int writeHeader( file )
FILE *file;
{
  int i;
  char number[W_INTBUF];
  sprintf( number, "%d", header.entries );
  for ( i = 0; i < sizeof( header.magic  ); i++ )
    fputc( header.magic[i], file );
  for ( i = 0; i < sizeof( header.reposowner ); i++ )
    fputc( header.reposowner[i], file );    
  for ( i = 0; i < sizeof( header.logfile  ); i++ )
    fputc( header.logfile[i], file );    
  for ( i = 0; i < sizeof( number  ); i++ )
    fputc( number[i], file );      
  return !ferror( file );
}


/****************************************************************************
  purpose: write the entry at index to a file. all fields are stored as 
           strings making the repository platform independent.
  pre    : file is a FILE* to the repository opened for writing
  post   :
****************************************************************************/
int writeEntry( file , index)
FILE *file;
int  index;
{
  int i;
  for ( i = 0; i < sizeof( entries[index].database ); i++ )
    fputc( entries[index].database[i], file );
  for ( i = 0; i < sizeof( entries[index].schemaname ); i++ )
    fputc( entries[index].schemaname[i], file );    
  for ( i = 0; i < sizeof( entries[index].osusername ); i++ )
    fputc( entries[index].osusername[i], file );    
  for ( i = 0; i < sizeof( entries[index].password ); i++ )
    fputc( entries[index].password[i], file );    
  return !ferror( file );
}

/****************************************************************************
  purpose: read the entry at index from file. all fields are stored as 
           strings making the repository platform independent.
  pre    : file is a FILE* to the repository opened for reading
  post   :
****************************************************************************/
int readEntry( file, index )
FILE *file;
int index;
{ 
  int i;
  for ( i = 0; i < sizeof( entries[index].database ); i++ )  
    entries[index].database[i] = fgetc( file );
  for ( i = 0; i < sizeof( entries[index].schemaname ); i++ )
    entries[index].schemaname[i] = fgetc( file );    
  for ( i = 0; i < sizeof( entries[index].osusername ); i++ )
    entries[index].osusername[i] = fgetc( file );    
  for ( i = 0; i < sizeof( entries[index].password ); i++ )
    entries[index].password[i] = fgetc( file );    
  return !ferror( file );    
}

/****************************************************************************
  purpose: lock repository file for read.
  pre    : file is a FILE* to the repository opened for reading
  post   :
****************************************************************************/
int readLock( FILE *file )
{
  int r = -1;
  int c = 0;
  struct flock all;
  struct timespec req;
  req.tv_sec = 0;
  req.tv_nsec = LOCK_SLEEP;
  all.l_type = F_RDLCK;
  all.l_whence = SEEK_SET;
  all.l_start = 0;
  all.l_len = 10;
  r = fcntl( fileno( file ),
             F_SETLK,
             &all );
  while( r == -1 && ( errno == EAGAIN || errno == EACCES ) && c < LOCK_RETRIES )
  {
    nanosleep( &req, NULL );
    r = fcntl( fileno( file ),
                F_SETLK,
                &all );
    fprintf( stdout, "sleeping %i\n", c );
    c++;
  }
  return r;
         
}

/****************************************************************************
  purpose: lock repository file for write.
  pre    : file is a FILE* to the repository opened for writing
  post   :
****************************************************************************/
int writeLock( FILE *file )
{
  int r = -1;
  int c = 0;
  struct flock all;
  struct timespec req;
  req.tv_sec = 0;
  req.tv_nsec = LOCK_SLEEP;
  all.l_type = F_WRLCK;
  all.l_whence = SEEK_SET;
  all.l_start = 0;
  all.l_len = 10;
  r = fcntl( fileno( file ),
             F_SETLK,
             &all );
  while( r == -1 && ( errno == EAGAIN || errno == EACCES ) && c < LOCK_RETRIES )
  {
    nanosleep( &req, NULL );
    r = fcntl( fileno( file ),
                F_SETLK,
                &all );
    c++;
  }
  return r;
}

/****************************************************************************
  purpose: unlock repository.
  pre    : file is a opened FILE* to the repository
  post   :
****************************************************************************/
int unLock( FILE *file )
{
  int r = -1;
  struct flock all;
  all.l_type = F_UNLCK;
  all.l_whence = SEEK_SET;
  all.l_start = 0;
  all.l_len = 10;
  return fcntl( fileno( file ),
                F_SETLK,
                &all );
}

/****************************************************************************
  purpose: read in the repository file into memory. the globals header and 
           entries are filled.
  pre    : reposname filled
  post   : the password file is read into memory.
****************************************************************************/
void readRepos()
{
  FILE *file = fopen( reposname, "rb");
  if ( file )
  {
    // obtain read (shared) lock on the file, blocking
    int r = readLock( file );
    if ( r == -1 )
    {
      fprintf( stderr, "error %d locking %s.\n", errno, reposname );
      terminate();      
    }    
    if ( readHeader( file ) )
    {
      if ( strncmp( header.magic, MAGIC, W_MAGIC ) != 0 )
      {
        unLock( file );              
        fprintf( stderr, "%s is not a valid OPR repository.\n", reposname);
        terminate();
      }
      if ( header.entries )
      {
        int i;
        for ( i = 0; i < header.entries; i++ )
          if ( !readEntry( file, i ) )
          {
            unLock( file );                  
            fprintf( stderr, "read failure in %s (entry).\n", reposname);
            terminate();
          }
      }
    } else
    {
      fprintf( stderr, "read failure in %s (header).\n", reposname);
      terminate();
    }
    unLock( file );          
    fclose( file );
  } else
  {
    fprintf( stderr, "unable to open %s for reading.\n", reposname);
    terminate();
  }
}

/****************************************************************************
  purpose: write the repository from memory to file.
  pre    :
  post   : repository is written to file.
****************************************************************************/
void writeRepos()
{
  FILE *file = fopen( reposname, "w+b" );
  if ( file )
  {    
    int r;
    qsortEntries();
    // obtain write lock on the file, blocking
    r = writeLock( file );
    if ( r == -1 )
    {
      fprintf( stderr, "error %d locking %s.\n", errno, reposname );
      terminate();      
    }
    if ( writeHeader( file) )
    {
      if ( header.entries )
      {
        int i;
        for ( i = 0; i < header.entries; i++ )
          if ( !writeEntry( file, i ) )
          {
            unLock( file );            
            fprintf( stderr, "write failure in %s (entry).\n", reposname );
            terminate();
          }
      }
    } else
    {
      unLock( file );      
      fprintf( stderr, "write failure in %s (header).\n", reposname );
      terminate();
    }
    unLock( file );    
    fclose( file );
  } else
  {
    fprintf( stderr, "unable to open %s for writing.\n", reposname );
    terminate();
  }
}

/****************************************************************************
  purpose: search the repository for a database, schemaname,
           osusername combination. the entries are sorted so a
           binary search can be used.
  pre    : the repository is read into memory by the readRepos function.
  post   : if an entry is found return its index, return -1 otherwise.
****************************************************************************/
int findEntry( database, schemaname, osusername )
char *database;
char *schemaname;
char *osusername;
{
  int m, r, l, cmp, result;
  Entry lookfor;
  result = -1;

  strncpy( lookfor.database, database, sizeof( lookfor.database ) );
  strncpy( lookfor.schemaname, schemaname, sizeof( lookfor.schemaname ) );
  strncpy( lookfor.osusername, osusername, sizeof( lookfor.osusername ) );
  l = 0;
  r = header.entries - 1;
  while ( r >= l )
  {
    m = ( l + r ) / 2;
    cmp = compareEntries( &lookfor, &entries[m] );
    if ( cmp < 0 ) r = m - 1;
    else if ( cmp > 0 ) l = m + 1;
    else
    {
      result=m;
      break;
    }
  }
  return result;
}

/****************************************************************************
  purpose: print command line usage on stdout
  pre    :
  post   :
****************************************************************************/
void printHelp()
{
  fprintf( stdout, "Oracle Password Repository 1.1.12\n" );
  fprintf( stdout, "GNU GPL by Jan-Marten Spit\n" );  
  fprintf( stdout, "http://sourceforge.net/projects/opr\n\n" );
  fprintf( stdout, "usage: \n" );
  fprintf( stdout, "- create repository                    : "
                   "opr -c\n" );  
  fprintf( stdout, "- list contents of repository          : "
                   "opr -l\n\n" );                       
  fprintf( stdout, "- add (grant) password                 : "
                   "opr -a (-f) <database> <schemaname> <osuser>\n" );  
  fprintf( stdout, "                                         "
                   "(-f forces entry addition without database verification)\n" );
  fprintf( stdout, "- read password                        : "
                   "opr -r <database> <schemaname>\n" );                   
  fprintf( stdout, "- modify password                      : "
                   "opr -m <database> <schemaname>\n" );                     
  fprintf( stdout, "- delete (revoke) password             : "
                   "opr -d <database> <schemaname> <osuser>\n\n" );  
  fprintf( stdout, "- enable logging                       : "
                   "opr +g <logfile>\n" );
  fprintf( stdout, "- disable logging                      : "
                   "opr -g\n\n" );                     
  fprintf( stdout, "- crosscheck repository with all dbs   : "
                   "opr -x \n" );  
  fprintf( stdout, "- crosscheck repository with single db : "
                   "opr -x <database>\n\n" );  
  fprintf( stdout, "- export repository to file            : "
                   "opr -e <filename> \n" );
  fprintf( stdout, "- import repository from file          : "
                   "opr -i <filename> \n\n" );
}

/****************************************************************************
  purpose: ask the user to enter a password. it is asked twice to
           avoid typos. the passwords are not echoed to the terminal
           when typed.
  pre    : pwd points to a buffer of at least W_PASSWORD chars.
  post   : returns 1 when a password is entered correctly, 0
           otherwise
****************************************************************************/
int askPassword( pwd )
char* pwd;
{
  char pwd1[W_PASSWORD];
  char pwd2[W_PASSWORD];
  int i;
  printf( "please enter the password : " );
  noecho();
  fgets( pwd1, W_PASSWORD, stdin );
  echo();
  printf( "\nplease re-enter the password : " );
  noecho();
  fgets( pwd2, W_PASSWORD, stdin );
  echo();
  printf( "\n" );
  for ( i = W_PASSWORD - 1; i >= 0; i-- )
  {
    if ( pwd1[i] == '\n' ) pwd1[i] = 0; 
    if ( pwd2[i] == '\n' ) pwd2[i] = 0;
  }        
  if ( strncmp( pwd1, pwd2, W_PASSWORD ) == 0 )
  {
    strncpy( pwd, pwd1, W_PASSWORD);
    return 1;
  } else return 0;
}

/****************************************************************************
  purpose: read the value of the OPRREPOS shell variable.
  pre    :
  post   : if the shell variable is set, it is assigned to the global
           'reposname'. opr terminates otherwise.
****************************************************************************/
void getEnvironment()
{
  char *r = getenv( OPRREPOS );
  if ( r )
    strncpy( reposname, r, sizeof(reposname) );
  else {
    fprintf( stderr, "environment variable '%s' not set.\n", OPRREPOS );
    exit( -1 );
  }
}

/****************************************************************************
  purpose: fetch the operating system username of the invoker of
           this executable. the uid is examined.
  pre    :
  post   : the UNIX username is assigned to the global osusername. opr
           terminates if this username cannot be determined.
****************************************************************************/
void osUserName()
{
  uid_t uid;
  struct passwd *pwd;
  uid = getuid();
  pwd = getpwuid(uid);
  if ( pwd )
  {
    strncpy( osusername, pwd->pw_name, sizeof(osusername) );     
  } else
  {
    fprintf( stderr, "getpwuid failed.\n" );
    terminate();
  }  
}

/****************************************************************************
  purpose: create a new repository file
  pre    : file does not exist.
  post   : a new password file is created. opr terminates when the
           file already exists or when writing fails.
****************************************************************************/
void createRepos()
{
  FILE * file = fopen( reposname, "r");
  if ( file )
  {
    fclose( file );
    fprintf( stderr, "file %s already exists.\n", reposname );
    terminate();
  }
  file = fopen( reposname, "w" );
  if ( file )
  {
    memset( &header, 0, sizeof( header ) );   
    strncpy( header.magic, MAGIC, sizeof( header.magic ) );
    strncpy( header.reposowner, osusername, sizeof( header.reposowner) );
    if ( !writeHeader( file ) )
    {
      fprintf( stderr, "failure writing to %s (header).\n", reposname );
      exit( -1 );
    }
    fclose( file );
    if ( chmod( reposname,  S_IRUSR | S_IWUSR ) )
    {
      fprintf( stderr,
               "chmod failed on repository %s with errno %d.\n",
               reposname,
               errno);
      terminate();
    }
    fprintf( stdout, "repository %s created.\n", reposname );
  } else
  {
    fprintf( stderr, "unable to open %s for writing.\n", reposname );
    exit( -1 );
  }
}

/****************************************************************************
  purpose: find the password for the given ( database, schemaname, osusername) 
           tuple.
  pre    : the password file is read into memory by readRepos.
  post   : if the entry is found, and the osuser is allowed to,
           then the password is echoed to sdtout.
           The MSG_SECURITY is printed to stderr otherwise.
****************************************************************************/
void readPassword( database,schemaname )
char* database;
char* schemaname;
{
  int e;
  readRepos();

  strtoupper( database );
  strtolower( schemaname );

  e=findEntry( database, schemaname, osusername );
  if ( e == -1 ) 
  {
    logEntryLine( 1, database, schemaname, osusername, MSG_SECURITY);
    fprintf( stderr, "%s\n", MSG_SECURITY );
    terminate();
  } else {
    cryptEntry( &entries[e] );
    printf( entries[e].password );
    logEntryLine( 0, database, schemaname, osusername, "request ok");    
  }
}

/****************************************************************************
  purpose: find the first entry for a ( database, schemaname) tuple.
  pre    : readRepos
  post   : return -1 when entry not found, index of the entry otherwise.
****************************************************************************/
int schemaPassword( database, schemaname )
char *database;
char *schemaname;
{
  int l, r, m, found;
  l = 0;
  r = header.entries - 1;
  found = -1;
  while ( r >= l )
  {
    m = ( l + r ) / 2 ;
    if ( strncmp( database, entries[m].database, W_DATABASE ) < 0 ) r = m - 1;
    else
    if ( strncmp( database, entries[m].database, W_DATABASE ) > 0 ) l = m + 1;
    else
    if ( strncmp( schemaname, entries[m].schemaname, W_SCHEMANAME ) < 0 ) 
      r = m - 1;
    else
    if ( strncmp( schemaname, entries[m].schemaname, W_SCHEMANAME ) > 0 ) 
      l = m + 1;
    else 
    {
      found = m;
      break;
    }
  }   
  return found;
}

/****************************************************************************
  purpose: add a new entry to the password file.
  pre    : readRepos
  post   : if the invoking osuser is the repository owner, the
           entry does not exist and a consistent password
           is entered, a new entry is added.
****************************************************************************/
void addEntry( database, schemaname, osuser, noverify )
char *database;
char *schemaname;
char *osuser;
int noverify;
{
  char pwd[W_PASSWORD];
  int existpwd;

  readRepos();
  isReposOwner();
  loadOraLibs();

  strtoupper( database );
  strtolower( schemaname );

  if ( strlen( database ) > W_DATABASE - 1 )
  {
    fprintf( stderr, 
             "database name too long (max %d chars).\n", 
             W_DATABASE-1 );
    terminate();             
  }
  if ( strlen( schemaname ) > W_SCHEMANAME - 1 )
  {
    fprintf( stderr, 
             "schemaname name too long (max %d chars).\n", 
             W_SCHEMANAME-1 );    
    terminate();             
  }
  if ( header.entries == MAX_ENTRIES )
  {
    fprintf( stderr,
             "max_entries reached (max %d entries).\n",
             MAX_ENTRIES );
    terminate();             
  }
  if ( findEntry( database, schemaname, osuser ) != -1 )
  {
    fprintf( stderr, "entry exists.\n" );
    terminate();
  }
  existpwd = schemaPassword( database, schemaname );
  if ( existpwd != -1 )
  {
    cryptEntry( &entries[existpwd] );
    strncpy( entries[header.entries].database,
             database,
             sizeof( entries[header.entries].database ) );
    strncpy( entries[header.entries].schemaname,
             schemaname,
             sizeof( entries[header.entries].schemaname ) );
    strncpy( entries[header.entries].osusername,
             osuser,
             sizeof( entries[header.entries].osusername ) );  
    strncpy( entries[header.entries].password,
             entries[existpwd].password,
             sizeof( entries[header.entries].password ) );  
    cryptEntry( &entries[existpwd] );                                
    cryptEntry( &entries[header.entries] );         
  } else
  if ( askPassword( pwd ) )
  {
    if ( noverify != 1 && !checkDBPassword( database,
                                            schemaname,
                                            pwd ) )
    {
      fprintf( stderr, "entry not added.\n" );
      terminate();
    }
    strncpy( entries[header.entries].database,
             database,
             sizeof( entries[header.entries].database) );
    strncpy( entries[header.entries].schemaname,
             schemaname,
             sizeof( entries[header.entries].schemaname ) );
    strncpy( entries[header.entries].osusername,
             osuser,
             sizeof( entries[header.entries].osusername) );
    strncpy( entries[header.entries].password,
             pwd,
             sizeof( entries[header.entries].password) );
    cryptEntry( &entries[header.entries] );             
  } else
  {
    printf( "password not entered correctly.\n" );
    terminate();
  }
  header.entries++;
  writeRepos();

  fprintf( stdout,
           "entry (%s, %s, %s) added",
           database,
           schemaname,
           osuser );
  if ( noverify == 1 )
    fprintf( stdout, " (not verified)" );
  fprintf( stdout, ".\n" );

  logEntryLine( 0, database, schemaname, osuser, "entry added" );
}

/****************************************************************************
  purpose: delete an entry from the password file.
  pre    : readRepos.
  post   : if the invoking osuser is the repository owner, the
           entry exists, then the given entry is deleted.
****************************************************************************/
void deleteEntry( database, schemaname, osuser )
char *database;
char *schemaname;
char *osuser;
{
  int e, i;
  readRepos();
  isReposOwner();

  strtoupper( database );
  strtolower( schemaname );

  e = findEntry( database, schemaname, osuser );
  if ( e == -1 )
  {
    fprintf( stderr, "entry does not exist.\n" );
    terminate();
  } else
  {
    for ( i = e + 1; i < header.entries; i++ )
    {
      entries[i-1]=entries[i];
    }
    header.entries--;
    writeRepos();
    fprintf( stdout,
             "entry (%s,%s,%s) deleted.\n",
             database,
             schemaname,
             osuser );
    logEntryLine( 0, database, schemaname, osuser, "entry deleted");
  }
}

/****************************************************************************
  purpose: modify an entry in the password file.
  pre    : readRepos.
  post   : if the invoking osuser is the repository owner and the
           entry exists, the given entry is modified.
****************************************************************************/
void modifyEntry( database, schemaname )
char *database;
char *schemaname;
{
  int e, c, i;
  char pwd[W_PASSWORD];
  int synced = 0;

  strtoupper( database );
  strtolower( schemaname );

  readRepos();
  isReposOwner();
  loadOraLibs();
  if ( askPassword( pwd ) )
  {
    c=0;
    for ( i = 0; i < header.entries; i++ )
    {
      if ( strncmp( entries[i].database, database, W_DATABASE ) == 0 &&
           strncmp( entries[i].schemaname, schemaname, W_SCHEMANAME ) == 0 )
      {
        if ( !synced )
        {
          cryptEntry( &entries[i] );
          if ( changeDBPassword( entries[i].database,
                                 entries[i].schemaname,
                                 entries[i].password,
                                 pwd ) )
             synced = 1;
           else
           {
             fprintf( stderr, "nothing modified.\n");
             terminate();
           }  
         }                   
        strncpy( entries[i].password,
                 pwd,
                 sizeof( entries[i].password ) );
        cryptEntry( &entries[i] );                 
        c++;
      }
    }
    writeRepos();
    fprintf( stdout, "%d entries modified.\n",
             c );
    logEntryLine( 0, database, schemaname, "", "entry modified");
  } else
  {
    fprintf( stderr, "password not entered correctly.\n" );
    terminate();
  }
}

/****************************************************************************
  purpose : list the contents of the repository
  pre     : the password file is read into memory
  post    : entries are printed to stdout
****************************************************************************/
void listEntries()
{
  int i;
  readRepos();
  if ( strncmp( header.reposowner, osusername, W_OSUSERNAME ) == 0 )
  {
    if ( strlen( header.logfile ) > 0 )
      printf( "logfile is %s. \n", header.logfile );
    else
      printf( "logging disabled. \n" );
    printf( "contents of repository %s: \n", reposname );
    printf( "------------------------------------------------------------\n" );
    printf( "%-20s%-20s%-20s\n","database","schemaname","osuser" );
    printf( "------------------------------------------------------------\n" );
    for ( i = 0; i < header.entries; i++ )
    {
      printf( "%-20s%-20s%-20s\n",
              entries[i].database,
              entries[i].schemaname,
              entries[i].osusername );
    }
    printf( "%d entries.\n", header.entries );
  } else
  {
    int c = 0;
    printf( "contents of repository %s: \n", reposname );
    printf( "------------------------------------------------------------\n" );
    printf( "%-20s%-20s%-20s\n","database","schemaname","osuser" );
    printf( "------------------------------------------------------------\n" );
    for ( i = 0; i < header.entries; i++ )
    {
      if ( strncmp( osusername, entries[i].osusername, W_OSUSERNAME ) == 0 )    
      {
        printf( "%-20s%-20s%-20s\n",
                entries[i].database,
                entries[i].schemaname,
                entries[i].osusername );
        c++;
      }         
    }
    printf( "%d entries.\n", c );  
  }  
}

/****************************************************************************
  purpose : create an 'export' file of the repository. the export contains
            one entry per line, the strings terminated by a ':'  
****************************************************************************/
void exportRepos( filename )
char *filename;
{
  readRepos();
  isReposOwner();
  if ( header.entries > 0 )
  {
    int i;
    FILE *file;
    file = fopen( filename, "w" );
    if ( file )
    {
      for ( i = 0; i < header.entries; i++ )
      {
        int j;
        for ( j = 0; j < W_DATABASE; j++ ) 
          fputc( entries[i].database[j], file );
        for ( j = 0; j < W_SCHEMANAME; j++ )  
          fputc( entries[i].schemaname[j], file );
        for ( j = 0; j < W_OSUSERNAME; j++ ) 
          fputc( entries[i].osusername[j], file );          
        for ( j = 0; j < W_PASSWORD; j++ ) 
          fputc( entries[i].password[j], file );          
      }
  
      fclose( file );
      if ( chmod( filename,  S_IRUSR | S_IWUSR ) )
      {
        fprintf( stderr,
                 "chmod failed on export file %s with errno %d\n",
                 filename,
                 errno );
        terminate();
      }
      fprintf( stdout, "export %s created.\n", filename );
    } else
    {
      fprintf( stderr, "unable to open %s for writing\n", filename );
      terminate();
    }
  } else printf( "nothing to export.\n" );
}

/****************************************************************************
  purpose : import file into the repository. the import file must be in
            'export' format. see exportRepos.
****************************************************************************/
void importRepos( filename )
char *filename;
{
  FILE *file;
  Entry entry;
  readRepos();
  isReposOwner();
  file = fopen( filename, "r");
  if ( file )
  {
    int c;  
    c = 0;
    while ( !feof( file ) )
    {
      int j, i;    
      char t;
      long int p;
      t = fgetc( file );
      p = ftell( file );
      if ( feof( file ) ) break; else fseek( file, p-1, SEEK_SET ); 
      memset( &entry, 0, sizeof( entry ) );         
      for ( j = 0; j < W_DATABASE; j++ ) 
        entry.database[j] = fgetc( file );      
      for ( j = 0; j < W_SCHEMANAME; j++ ) 
        entry.schemaname[j] = fgetc( file );
      for ( j = 0; j < W_OSUSERNAME; j++ ) 
        entry.osusername[j] = fgetc( file );        
      for ( j = 0; j < W_PASSWORD; j++ ) 
        entry.password[j] = fgetc( file );        
        
      i = findEntry( entry.database, entry.schemaname, entry.osusername );
      if ( i == -1 )
      {                           
        c++;              
        entries[header.entries] = entry;
        header.entries++;
        qsortEntries();
      } else printf( "entry (%s, %s, %s ) exists.\n",
                      entry.database,
                      entry.schemaname,
                      entry.osusername );
    }
    fclose( file );
    writeRepos();
    fprintf( stdout, "%d entries imported.\n", c );
  } else
  {
    fprintf( stderr, "unable to open %s for reading.\n", filename);
    terminate();
  }
}

/****************************************************************************
  purpose : do a crosscheck between repository and database.
****************************************************************************/
void crossCheckAllDB( )
{
  readRepos();
  isReposOwner();
  loadOraLibs();
  if ( header.entries > 0 )
  {
    int i;

    char prevdatabase[W_DATABASE];
    char prevschemaname[W_SCHEMANAME];    
    
    fprintf( stdout, 
             "checking repository %s.\n",
             reposname );
      
    strncpy( prevdatabase, "", sizeof( prevdatabase ) );
    strncpy( prevschemaname, "", sizeof( prevschemaname ) );        
     
    for (i = 0 ; i < header.entries ; i++ )
    {
      if ( strncmp( prevdatabase, entries[i].database, W_DATABASE ) != 0 ||
           strncmp( prevdatabase, entries[i].database, W_DATABASE ) == 0 &&
           strncmp( prevschemaname, entries[i].schemaname, W_SCHEMANAME ) != 0 )
      {
        strncpy( prevdatabase, 
                 entries[i].database, 
                 sizeof( prevdatabase ) );
        strncpy( prevschemaname, 
                 entries[i].schemaname, 
                 sizeof( prevschemaname ) );              
        cryptEntry( &entries[i] );                
        if ( checkDBPassword( entries[i].database,
                              entries[i].schemaname,
                              entries[i].password )  )
          fprintf( stdout,
                   "entry %s@%s ok.\n",
                   entries[i].schemaname,
                   entries[i].database );
        else                      
          fprintf( stdout, 
                   "ERROR: entry %s@%s invalid.\n",
                   entries[i].schemaname,
                   entries[i].database );
      }  
    }  
  } else printf( "nothing to crosscheck.\n" );
}

/****************************************************************************
  purpose : do a crosscheck between repository and a single database.
****************************************************************************/
void crossCheckSingleDB( database )
char *database;
{
  readRepos();
  isReposOwner();
  loadOraLibs();

  strtoupper( database );

  if ( header.entries > 0 )
  {
    int i;

    char prevschemaname[W_SCHEMANAME];    
    
    fprintf( stdout, 
             "checking repository %s for database %s.\n",
             reposname, database );
      
    strncpy( prevschemaname, "", sizeof( prevschemaname ) );        
     
    for (i = 0 ; i < header.entries ; i++ )
    {
      if ( strncmp( database, entries[i].database, W_DATABASE ) == 0 )
      {
	if ( strncmp( prevschemaname, entries[i].schemaname, W_SCHEMANAME ) != 0 )
	{
          strncpy( prevschemaname, 
                   entries[i].schemaname, 
                   sizeof( prevschemaname ) );              
          cryptEntry( &entries[i] );                
          if ( checkDBPassword( entries[i].database,
                                entries[i].schemaname,
                                entries[i].password )  )
            fprintf( stdout,
                     "entry %s@%s ok.\n",
                     entries[i].schemaname,
                     entries[i].database );
          else               
            fprintf( stdout, 
                     "ERROR: entry %s@%s invalid.\n",
                     entries[i].schemaname,
                     entries[i].database );
        }
      }  
    }  
  } else printf( "nothing to crosscheck.\n" );
}

/****************************************************************************
  purpose : enable logging
****************************************************************************/
void enableLog( filename )
char *filename;
{
  FILE *file;
  readRepos();
  isReposOwner();
  file = fopen ( filename, "a" );
  if ( file )
  {
    fclose( file);
    if ( chmod( filename, S_IRUSR | S_IWUSR ) )
    {
      fprintf( stderr,
               "chmod failed on log file %s with errno %d.\n",
               filename,
               errno );
      terminate();
    }
    strncpy( header.logfile, filename, sizeof( header.logfile ) );
    logLine( 0, "logging enabled" );    
    writeRepos();
    printf( "logging enabled to %s.\n", header.logfile );
  } else
  {
    fprintf( stderr, "unable to open %s for append.\n", filename );
    terminate();
  }
}

/****************************************************************************
  purpose : disable logging
****************************************************************************/
void disableLog()
{
  readRepos();
  isReposOwner();
  logLine( 0, "logging disabled." );  
  strncpy( header.logfile , "", 1 );
  printf( "logging disabled.\n", header.logfile );  
  writeRepos();
}


/****************************************************************************
  purpose : main function.
****************************************************************************/
int main(argc,argv)
int argc;
char *argv[];
{
  getEnvironment();
  osUserName();
  if ( argc > 1 )
  {
    /* opr -c */
    if ( strncmp( argv[1], "-c", 2 ) == 0 )
    {
      if ( argc == 2 ) createRepos();
        else printHelp();
    } else
    /* opr -r <database> <schemaname> */
    if ( strncmp( argv[1], "-r", 2 ) == 0 )
    {
      if ( argc == 4 ) readPassword( argv[2], argv[3] );
        else printHelp();
    } else
    /* opr -a (-f) <database> <schemaname> <osuser> */
    if ( strncmp( argv[1], "-a", 2 ) == 0 )
    {
      if ( argc > 2 && strncmp( argv[2], "-f", 2 ) == 0 ) {
        if ( argc == 6 ) addEntry( argv[3], argv[4], argv[5], 1 );
          else printHelp();
      }
      else {
        if ( argc == 5 ) addEntry( argv[2], argv[3], argv[4], 0 );
          else printHelp();
      }
    } else
    /* opr -d <database> <schemaname> <osuser> */
    if ( strncmp( argv[1], "-d", 2 ) == 0 )
    {
      if ( argc == 5 ) deleteEntry( argv[2], argv[3], argv[4] );
        else printHelp();
    } else
    /* opr -m <database> <schemaname> */
    if ( strncmp( argv[1], "-m", 2 ) == 0 )
    {
      if ( argc == 4 ) modifyEntry( argv[2], argv[3] );
      else printHelp();
    } else
    /* opr -e <filename> */
    if ( strncmp( argv[1], "-e", 2 ) == 0 )
    {
      if ( argc == 3 ) exportRepos(argv[2]);
        else printHelp();
    } else
    /* opr -i <filename> */
    if ( strncmp( argv[1], "-i", 2 ) == 0 )
    {
      if ( argc == 3 ) importRepos(argv[2]);
        else printHelp();
    } else    
    /* opr -x <filename> */
    if ( strncmp( argv[1], "-x", 2 ) == 0 )
    {
      if ( argc == 2 ) crossCheckAllDB();
      else if ( argc == 3 ) crossCheckSingleDB( argv[2] );
        else printHelp();
    } else
    /* opr -g*/
    if ( strncmp( argv[1], "-g", 2 ) == 0 )
    {
      if ( argc == 2 ) disableLog();
        else printHelp();
    } else    
    /* opr +g <filename> */
    if ( strncmp( argv[1], "+g", 2 ) == 0 )
    {
      if ( argc == 3 ) enableLog(argv[2]);
        else printHelp();
    } else
    /* opr -l */
    if ( strncmp( argv[1], "-l", 2 ) == 0 )
    {
      if ( argc == 2 ) listEntries();
        else printHelp();
    } else printHelp();
  } else printHelp();
  return 0;
}

