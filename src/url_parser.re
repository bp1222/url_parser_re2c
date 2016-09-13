#include <stdlib.h>
#include <string.h>
#include "url_parser.h"

const char *marker;
const char *url_str;

const char *YYMARKER;

/*!re2c
    re2c:define:YYCTYPE = "unsigned char";
    re2c:define:YYCURSOR = url_str;
    re2c:yyfill:enable = 0;

    EOF = "\x00";
    ALPHA = [a-zA-Z];
    DIGIT = [0-9];
    HEXDIG = [0-9a-fA-F];
    SUB_DELIMS = [!$&'()*+,;=];
    GEN_DELIMS = [:/?#\[\]@];
    RESERVED = GEN_DELIMS | SUB_DELIMS;
    UNRESERVED = ALPHA | DIGIT | [-._~];
    PCT_ENCODED = "%" HEXDIG HEXDIG;
    PCHAR = UNRESERVED | PCT_ENCODED | SUB_DELIMS | ":" | "@";
*/

int url_parse_scheme(URL *url)
{
    marker = url_str;
/*!re2c
    SCHEME = ALPHA (ALPHA | DIGIT | [+-.])+ ":";

    EOF { url_str--; return 0; }
    "" { return 0; }
    SCHEME {
        int len = url_str - marker - 1;
        url->scheme = get_token(len);
        return 1;
    }
*/
}

void url_parse_authority_userinfo (URL *url)
{
    marker = url_str;
/*!re2c
    USERINFO = (UNRESERVED | PCT_ENCODED | SUB_DELIMS | ":")*;

    EOF { url_str--; return; }
    "" { return; }
    USERINFO "@" {
        int len = url_str - marker - 1;
        char* userinfo = get_token(len);
        url->userinfo = userinfo;
        return;
    }
*/
}

void url_parse_authority_host (URL *url)
{
    marker = url_str;
    int incr = 0;
/*!re2c
    //
    // IP Address Formats
    //
    DEC_OCTET = DIGIT | [1-9] DIGIT | "1" DIGIT{2} | "2" [0-4] DIGIT | "25" [0-5];
    IPV4ADDR = (DEC_OCTET "."){3} DEC_OCTET;
    H16 = HEXDIG{1,4};
    LS32 = (H16 ":" H16) | IPV4ADDR;
    IPV6ADDR = "[" (
        (H16 ":"){7,7} H16|
        (H16 ":" ){1,7} ":" |
        (H16 ":" ){1,6} ":" H16|
        (H16 ":" ){1,5}( ":" H16){1,2}|
        (H16 ":" ){1,4}( ":" H16){1,3}|
        (H16 ":" ){1,3}( ":" H16){1,4}|
        (H16 ":" ){1,2}( ":" H16){1,5}|
        H16 ":" (( ":" H16){1,6})|
        ":" (( ":" H16){1,7}| ":" )|
        "fe80:" ( ":" H16){0,4} "%" [0-9a-zA-Z]{1,}|
        "::" ( "ffff" ( ":0" {1,4}){0,1} ":" ){0,1}IPV4ADDR|
        (H16 ":"){1,4} ":" IPV4ADDR
    ) "]";
    IPVFUTURE = "[v" HEXDIG+ "." (UNRESERVED | SUB_DELIMS | ":")+ "]";
    REG_NAME = (UNRESERVED | PCT_ENCODED | SUB_DELIMS)+;

    EOF { url_str--; return; }
    "" { return; }
    IPV4ADDR {
        url->host->type = IPV4ADDR;
        goto host;
    }
    IPV6ADDR {
        url->host->type = IPV6ADDR;
        incr = 1;
        goto host;
    }
    IPVFUTURE {
        url->host->type = IPVFUTUR;
        incr = 1;
        goto host;
    }
    REG_NAME {
        url->host->type = REGNAME;
        goto host;
    }
*/
host:;
    int len = url_str - marker;

    if (incr) {
        len -= 2;
        marker++;
    }

    char* host = get_token(len);
    strncpy (url->host->name, host, HOST_MAX_LEN < len + 1 ? HOST_MAX_LEN : len + 1);
    free (host);
}

void url_parse_authority_port (URL *url)
{
    marker = url_str;
/*!re2c

    EOF { url_str--; return; }
    "" { return; }
    ":" DIGIT* {
        marker++;
        int len = url_str - marker;
        char* port = get_token(len);
        url->port = atoi(port);
        free(port);
    }
*/
}

int url_parse_authority (URL *url)
{
/*!re2c
    EOF { url_str--; return 0; }
    "" { return 0; }
    "//" {
        goto authority;
    }
*/

authority:;
    url_parse_authority_userinfo(url);
    url_parse_authority_host(url);
    url_parse_authority_port(url);

    if (url->host->type != UNKNOWN) {
        return 1;
    } else {
        if (url->userinfo) free(url->userinfo);
        memset(&url->host->type, 0, sizeof(url->host->type));
        url->port = 0;
        return 0;
    }
}

int url_parse_path (URL *url)
{
    marker = url_str;
/*!re2c
    SEGMENT_NZ_NC = (UNRESERVED | PCT_ENCODED | SUB_DELIMS | "@")+;
    SEGMENT_NZ = PCHAR+;
    SEGMENT = PCHAR*;
    PATH_ABEMPTY = ("/" SEGMENT)*;
    PATH_ABSOLUTE = "/" (SEGMENT_NZ ("/" SEGMENT)*)?;
    PATH_NOSCHEME = SEGMENT_NZ_NC ("/" SEGMENT)*;
    PATH_ROOTLESS = SEGMENT_NZ ("/" SEGMENT)*;
    PATH = PATH_ABEMPTY | PATH_ABSOLUTE | PATH_NOSCHEME | PATH_ROOTLESS;

    EOF { url_str--; return 0; }
    "" { return 0; }
    PATH {
        int len = url_str - marker;
        url->path = get_token(len);
        return 1;
    }
*/
}

void url_parse_query_frag (URL *url)
{
query_frag:;
    marker = url_str;
/*!re2c
    QUERY = "?" (PCHAR | "/" | "?")*;
    FRAGMENT = "#" (PCHAR | "/" | "?")*;

    EOF { url_str--; return; }
    "" { return; }
    QUERY {
        marker++;
        int len = url_str - marker;
        url->query = get_token(len);
        goto query_frag;
    }
    FRAGMENT {
        marker++;
        int len = url_str - marker;
        url->fragment = get_token(len);
        return;
    }
*/
}

int url_parse (const char *input, URL *url)
{
    int retval = 0;
    url_str = input;

    if (url_parse_scheme(url)) {
        url_parse_authority(url);
        url_parse_path(url);
        url_parse_query_frag(url);
        retval = 1;
    } else {
        if (url_parse_authority(url)) {
            url_parse_path(url);
            url_parse_query_frag(url);
            retval = 1;
        } else if (strlen(url_str) && url_parse_path(url)) {
            url_parse_query_frag(url);
            retval = 1;
        }
    }
    return retval;
}

URL *url_create ()
{
    URL *url = (URL*) malloc (sizeof(URL));
    url->host = (Host*) malloc (sizeof(Host));

    url->scheme   = NULL;
    url->userinfo = NULL;
    url->host->type = UNKNOWN;
    memset(&url->host->type, 0, sizeof(url->host->type));
    url->port = 0;
    url->path = NULL;
    url->query = NULL;
    url->fragment = NULL;

    return url;
}

void url_free (URL *url)
{
    if (url->scheme) free (url->scheme);
    if (url->userinfo) free (url->userinfo);
    if (url->host) free (url->host);
    if (url->path) free (url->path);
    if (url->query) free (url->query);
    if (url->fragment) free (url->fragment);
    free (url);
}

char * get_token(int len)
{
    char *res = (char *) malloc (len + 1);
    int i = 0;
    for (; i < len; i++) res[i] = marker[i];
    res[i] = '\0';
    return res;
}
