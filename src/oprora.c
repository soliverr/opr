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

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
/* cross platform dynamic library abstraction */
#include <ltdl.h>
/* oracle call interface */
#include <oci.h>
/* 
 * oracle client libraries. extensions are overruled by lt_dlopenext
 * depending on the platform (.la, .so, .sl, .. )
 */
#define ORA_LIBCLIENT32 "/lib32/libclntsh.so"
#define ORA_LIBCLIENT "/lib/libclntsh.so"
#define MAX_LIB_PATH 1024

/* handle to the oci client library */
lt_dlhandle libclntsh_so;
int libclntsh_so_loaded = 0;

/* OCI functions */
sword (*ocierrorget)( dvoid*, ub4, text*, ub4*, text*, ub4, ub4 );
sword (*ocienvcreate)( OCIEnv**, ub4, CONST dvoid**, CONST dvoid**, 
                       CONST dvoid**, CONST void*, size_t, dvoid** );
sword (*ocihandlealloc)( CONST dvoid*, dvoid**, ub4, size_t, dvoid** );
sword (*ocihandlefree)( dvoid*, ub4 );
sword (*ociattrset)( dvoid*, ub4, dvoid*, ub4, ub4, OCIError* );
sword (*ociserverattach)( OCIServer*, OCIError*, CONST text*,
                          sb4, ub4 );
sword (*ocisessionbegin)( OCISvcCtx*, OCIError*, OCISession*,
                          ub4, ub4 );
sword (*ocisessionend)( OCISvcCtx*, OCIError*, OCISession*, ub4 );                          
sword (*ocipasswordchange)( OCISvcCtx *, OCIError *, CONST text *,
                            ub4, CONST text *, ub4, CONST text *,
                            sb4, ub4);

/****************************************************************************
load the oracle dynamic libraries manually. check the oratab to determine
ORACLE_HOME the location (using the *: entry), and only open libclntsh.so 
from that location, to prevent malicious libclntsh.so attacks by overriding
the ORACLE_HOME.
****************************************************************************/
void loadOraLibs()
{
  if ( !libclntsh_so_loaded ) {

    char libpath32[MAX_LIB_PATH];
    char libpath[MAX_LIB_PATH];
    char oratab_entry[MAX_LIB_PATH];  
    FILE *oratab;
    int found = 0;
    int i;    
    
    //init ltdl
    if ( lt_dlinit() )
    {
      fprintf( stderr, "error initializing libltdl: %s", lt_dlerror() );         
      exit(-1);      
    }
    
    //open oratab to get ORACLE_HOME
    
    if ( ! ( oratab = fopen( "/var/opt/oracle/oratab", "r" ) ) ) 
      oratab = fopen( "/etc/oratab", "r" );
    if ( ! oratab ) 
    { 
      fprintf( stderr, "unable to open the oratab\n" );      
      exit(-1);
    } else
    {
      while( fgets( oratab_entry, MAX_LIB_PATH, oratab ) )
      {      
        if ( strncmp( oratab_entry, "*:", 2 ) == 0 )
        {
          found = 1;          
          for( i = 2; i < MAX_LIB_PATH; i++ )
          {
            if ( oratab_entry[i] == ':' ) 
            {
              libpath[i-2] = 0;
              break;
            }
            libpath[i-2] = oratab_entry[i];
            if ( oratab_entry[i] == 0 ) break;          
          }
          break;
        }
      }
      fclose( oratab );
      if ( ! found ) 
      {
        fprintf( stderr, "no default (*:) entry found in the oratab\n" );         
        exit(-1);
      } else
      {
        strncpy( libpath32, libpath, MAX_LIB_PATH );
        strncat( libpath, ORA_LIBCLIENT, MAX_LIB_PATH - strlen( libpath ) - 1 );
        strncat( libpath32, ORA_LIBCLIENT32, MAX_LIB_PATH - strlen( libpath32 ) - 1 );
      }   
    }
    
    //load libclntsh.so library and get function pointers
    
    libclntsh_so = lt_dlopenext( libpath32 );
    if ( !libclntsh_so ) 
    {
      libclntsh_so = lt_dlopenext( libpath );
      if ( !libclntsh_so ) {
        fprintf( stderr, "unable to load oracle client libraries.\n" );
        fprintf( stderr, "tried: %s, %s", libpath32, libpath );
        fprintf( stderr, "%s\n", dlerror() );
        exit(-1);
      }
    }
    ocierrorget = lt_dlsym( libclntsh_so, "OCIErrorGet" );
    if ( !ocierrorget )
    {
      fprintf( stderr, "failed to locate function OCIErrorGet\n" );
      exit(-1);
    }
    ocienvcreate = lt_dlsym( libclntsh_so, "OCIEnvCreate" );
    if ( !ocienvcreate )
    {
      fprintf( stderr, "failed to locate function OCIEnvCreate\n" );
      exit(-1);
    }
    ocihandlealloc = lt_dlsym( libclntsh_so, "OCIHandleAlloc" );
    if ( !ocihandlealloc )
    {
      fprintf( stderr, "failed to locate function OCIHandleAlloc\n" );
      exit(-1);
    }
    ocihandlefree = lt_dlsym( libclntsh_so, "OCIHandleFree" );
    if ( !ocihandlefree )
    {
      fprintf( stderr, "failed to locate function OCIHandleFree\n" );
      exit(-1);
    }  
    ociattrset = lt_dlsym( libclntsh_so, "OCIAttrSet" );
    if ( !ociattrset )
    {
      fprintf( stderr, "failed to locate function OCIAttrSet\n" );
      exit(-1);
    }
    ociserverattach = lt_dlsym( libclntsh_so, "OCIServerAttach" );
    if ( !ociserverattach )
    {
      fprintf( stderr, "failed to locate function OCIServerAttach\n" );
      exit(-1);
    }
    ocisessionbegin = lt_dlsym( libclntsh_so, "OCISessionBegin" );
    if ( !ocisessionbegin )
    {
      fprintf( stderr, "failed to locate function OCISessionBegin\n" );
      exit(-1);
    }
    ocisessionend = lt_dlsym( libclntsh_so, "OCISessionEnd" );
    if ( !ocisessionend )
    {
      fprintf( stderr, "failed to locate function OCISessionEnd\n" );
      exit(-1);
    }
    ocipasswordchange = lt_dlsym( libclntsh_so, "OCIPasswordChange" );
    if ( !ociattrset )
    {
      fprintf( stderr, "failed to locate function OCIPasswordChange\n" );
      exit(-1);
    }

    libclntsh_so_loaded = 1;
  }
}

void unloadOraLibs()
{
  if ( libclntsh_so_loaded == 1 )
    lt_dlclose( libclntsh_so );
  lt_dlexit();
}

/****************************************************************************
check the OCI function result on an environment handle
****************************************************************************/
void printOraEnv( OCIEnv *env )
{
  char buffer[4096];
  sb4 errorcode;  
  if ( ocierrorget( (void*) env,
                    1,
                    0,
                    (sb4*)&errorcode,
                    (text*)&buffer,
                    4096,
                    OCI_HTYPE_ENV ) !=OCI_SUCCESS )
  {
    fprintf( stderr,
             "unable to get oracle error message.\n" );            
  } else
  {
    fprintf( stderr,
             "(env) %s",
             buffer );
  }
  
}


/****************************************************************************
check the OCI function result on an error handle
****************************************************************************/
void printOraError( OCIError *error )
{
  char buffer[4096];
  sb4 errorcode;  
  if ( ocierrorget( (void*) error,
                    1,
                    0,
                    (sb4*)&errorcode,
                    (text*)&buffer,
                    4096,
                    OCI_HTYPE_ERROR ) !=OCI_SUCCESS )
  {
    fprintf( stderr,
             "unable to get oracle error message.\n" );        
  } else
  {
    fprintf( stderr,
             "%s",
             buffer );
  }
  
}

/****************************************************************************
check the OCI function result on an error handle
****************************************************************************/
sword errcheck( sword    fresult,
                OCIError *error )
{
  switch ( fresult )
  {
    case OCI_SUCCESS           : return OCI_SUCCESS;
    case OCI_SUCCESS_WITH_INFO : return OCI_SUCCESS;
    case OCI_INVALID_HANDLE    : fprintf( stderr,
                                          "invalid handle.\n" );
                                 return OCI_ERROR;
    case OCI_ERROR             : printOraError( error );
                                 return OCI_ERROR;
    default                    : fprintf( stderr,
                                          "unhandled Oracle error %d.\n",
                                          fresult );
                                 return OCI_ERROR;
  }
}

/****************************************************************************
check the OCI function result on an error handle
****************************************************************************/
sword envcheck( sword    fresult,
                OCIEnv   *env )
{
  switch ( fresult )
  {
    case OCI_SUCCESS           : return OCI_SUCCESS;
    case OCI_SUCCESS_WITH_INFO : return OCI_SUCCESS;
    case OCI_INVALID_HANDLE    : fprintf( stderr,
                                          "invalid handle.\n" );
                                 return OCI_ERROR;
    case OCI_ERROR             : printOraEnv( env );
                                 return OCI_ERROR;
    default                    : fprintf( stderr,
                                          "unhandled Oracle error"
                                          " (environment) %d.\n",
                                          fresult );
                                 exit(-1);
  }
}

/****************************************************************************
change the oldpasswd to new passwd on the database. if anything goes wrong,
changeDBPassword returns 0, 1 if successfull.
****************************************************************************/
int changeDBPassword( char* database, 
                      char* schema, 
                      char* oldpasswd,
                      char* newpasswd )                     
{
  OCIEnv     *env;
  OCIError   *error;
  OCIServer  *server;
  OCISession *session;  
  OCISvcCtx  *service;
  int result = 1;

  /* create the environment handle */
  if ( ocienvcreate( &env, 
                     OCI_DEFAULT, 
                     (dvoid*) 0, 
                     0, 
                     0, 
                     0, 
                     (size_t) 0, 
                     (dvoid**) 0 ) != OCI_SUCCESS )
  {
    fprintf( stderr,
             "OCI environment initialization failure.\n" );
    result = 0;
  }
  /* allocate an error handle */
  if ( result && ( envcheck( ocihandlealloc( (dvoid*) env,
                                             (dvoid**) &error,                
                                             OCI_HTYPE_ERROR,
                                             0,
                                             (dvoid**) 0 ),                                             
                             env ) != OCI_SUCCESS ) ) result = 0;
  /* allocate a server handle */    
  if ( result &&  ( envcheck( ocihandlealloc( (dvoid*) env,
                                              (dvoid**) &server,                
                                              OCI_HTYPE_SERVER,
                                              0,
                                             (dvoid**) 0 ),
                              env ) != OCI_SUCCESS ) ) result = 0;
  /* attach to the database */                            
  if ( result && ( errcheck( ociserverattach( server, 
                                              error,
                                              (text*) database,
                                              strlen( database ),
                                              OCI_DEFAULT ),
                             error ) != OCI_SUCCESS ) ) result = 0;
  /* setup a service context */             
  if ( result && ( envcheck( ocihandlealloc( (dvoid*) env,
                                             (dvoid**) &service,                
                                             OCI_HTYPE_SVCCTX,
                                             0,
                                             (dvoid**) 0 ),
                             env ) != OCI_SUCCESS ) ) result = 0;
  /* set server in service context */
  if ( result && ( errcheck( ociattrset( (dvoid*) service,
                                         OCI_HTYPE_SVCCTX,
                                         (dvoid*) server,
                                         (ub4) 0,
                                         OCI_ATTR_SERVER,
                                         error ),
                             error ) != OCI_SUCCESS ) ) result = 0;   
  if ( result && ( envcheck( ocihandlealloc( (dvoid*) env,
                                             (dvoid**) &session,                
                                             OCI_HTYPE_SESSION,
                                             0,
                                             (dvoid**) 0 ),
                             env ) != OCI_SUCCESS ) ) result = 0;                 
  if ( result && ( errcheck( ociattrset( (dvoid*) service,
                                         OCI_HTYPE_SVCCTX,
                                         (dvoid*) session,
                                         (ub4) 0,
                                         OCI_ATTR_SESSION,
                                         error ),
                             error ) != OCI_SUCCESS ) ) result = 0;
  /* change the password */                            
  if ( result && ( errcheck( ocipasswordchange( service,
                                                error,
                                                (text*) schema,
                                                strlen( schema ),
                                                (text*) oldpasswd,
                                                strlen( oldpasswd ),
                                                (text*) newpasswd,
                                                strlen( newpasswd ),
                                                OCI_AUTH ),
                             error ) != OCI_SUCCESS ) ) result = 0;
                             
  /** all child handles are freed automatically by oracle */                              
  ocihandlefree( env, OCI_HTYPE_ENV );                       
        
  return result;                 
}

/****************************************************************************
checks the database/schema password combination by attempting a logon.
returns 1 on succes, 0 otherwise
****************************************************************************/
int checkDBPassword( char* database, 
                     char* schema, 
                     char* passwd )
{
  OCIEnv     *env;
  OCIError   *error;
  OCIServer  *server;
  OCISession *session;  
  OCISvcCtx  *service;
  int        authmode;
  int result = 1;

  /* create the environment handle */
  if ( ocienvcreate( &env, 
                     OCI_DEFAULT, 
                     (dvoid*) 0, 
                     0, 
                     0, 
                     0, 
                     (size_t) 0, 
                     (dvoid**) 0 ) != OCI_SUCCESS )
  {
    fprintf( stderr,
             "OCI environment initialization failure.\n" );
    return 0;
  }
  /* allocate an error handle */
  if ( result && ( envcheck( ocihandlealloc( (dvoid*) env,
                                             (dvoid**) &error,                
                                             OCI_HTYPE_ERROR,
                                             0,
                                            (dvoid**) 0 ),
                             env ) != OCI_SUCCESS ) ) result = 0;
  /* allocate a server handle */  
  if ( result && ( envcheck( ocihandlealloc( (dvoid*) env,
                                             (dvoid**) &server,                
                                             OCI_HTYPE_SERVER,
                                             0,
                                             (dvoid**) 0 ),
                             env ) != OCI_SUCCESS ) ) result = 0;                           
  /* attach to the database */                            
  if ( result && ( errcheck( ociserverattach( server, 
                                              error,
                                              (text*) database,
                                              strlen( database ),
                                              OCI_DEFAULT ),
                             error ) != OCI_SUCCESS ) ) result = 0;
  /* setup a service context */            
  if ( result && ( envcheck( ocihandlealloc( (dvoid*) env,
                                             (dvoid**) &service,                
                                             OCI_HTYPE_SVCCTX,
                                             0,
                                            (dvoid**) 0 ),
                             env ) != OCI_SUCCESS ) ) result = 0;
  /* set server in service context */
  if ( result && ( errcheck( ociattrset( (dvoid*) service,
                                         OCI_HTYPE_SVCCTX,
                                         (dvoid*) server,
                                         (ub4) 0,
                                         OCI_ATTR_SERVER,
                                         error ),
                             error ) != OCI_SUCCESS ) ) result = 0;
  /* allocate session handle */                 
  if ( result && ( envcheck( ocihandlealloc( (dvoid*) env,
                                             (dvoid**) &session,                
                                             OCI_HTYPE_SESSION,
                                             0,
                                             (dvoid**) 0 ),
                              env ) != OCI_SUCCESS ) ) result = 0;
  if ( result && ( errcheck( ociattrset( (dvoid*) service,
                                         OCI_HTYPE_SVCCTX,
                                         (dvoid*) session,
                                         (ub4) 0,
                                         OCI_ATTR_SESSION,
                                         error ),
                             error ) != OCI_SUCCESS ) ) result = 0;
  if ( result && ( errcheck( ociattrset( (dvoid*) session,
                                         OCI_HTYPE_SESSION,
                                         (dvoid*) schema,
                                         (ub4) strlen( schema ),
                                         OCI_ATTR_USERNAME,
                                         error ),
                             error ) != OCI_SUCCESS ) ) result = 0;
  if ( result && ( errcheck( ociattrset( (dvoid*) session,
                                         OCI_HTYPE_SESSION,
                                         (dvoid*) passwd,
                                         (ub4) strlen( passwd ),
                                         OCI_ATTR_PASSWORD,
                                         error ),
                             error ) != OCI_SUCCESS ) ) result = 0;

  if ( strncasecmp( schema, "sys", strlen( schema ) ) )
    authmode = OCI_DEFAULT;
  else
    authmode = OCI_SYSDBA;

  if ( result && ( errcheck( ocisessionbegin( service,
                                              error,
                                              session,
                                              OCI_CRED_RDBMS,
                                              authmode ),
                             error ) != OCI_SUCCESS ) ) result = 0;
                             
  if ( result && ( errcheck( ocisessionend( service,
                                            error,
                                            session,
                                            OCI_DEFAULT ),
                             error ) != OCI_SUCCESS ) ) result = 0;                               
                
  /** all child handles are freed automatically by oracle */                       
  ocihandlefree( env, OCI_HTYPE_ENV );                                
                             
  return result;                 
}

