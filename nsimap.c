/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1(the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis,WITHOUT WARRANTY OF ANY KIND,either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively,the contents of this file may be used under the terms
 * of the GNU General Public License(the "GPL"),in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License,indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above,a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * Author Vlad Seryakov vlad@crystalballinc.com
 *
 */

/*
 * nsimap.c -- Interface to c-client Mail library
 *
 * How it works
 *  Basically it is interface to c-client IMAP library
 *
 *  ns_imap command is used to open mail sessions and manupulate messages
 *
 *  ns_imap usage:
 *
 *    ns_imap sessions
 *      returns list with cusrrently opened sessions as
 *         { id opentime accesstime mailbox } ...
 *
 *    ns_imap gc
 *      performs garbage collection, closes inactive sessions according to
 *      config parameter timeout from config section ns/server/${server}/module/nsimap
 *
 *    ns_imap encode type data
 *    ns_imap decode type data
 *      performs encodeing/decoding given text according given format.
 *      type may be one of the following: base64 qprint, utf7
 *
 *    ns_imap striphtml text ?tags?
 *      strips dangerous HTML tags from the given HTML text,
 *      by default it removes body/title/div/object/frame tags.
 *      If tags are specified it will use them instead of internal list.
 *
 *    ns_imap open -mailbox mailbox ?-user u -password p -debug -expunge -anonymous -shortcache -readonly -halfopen -reopen?
 *      creates new mail session for specified mailbox. Optional parameters
 *      can be specified. Returns mail descriptor which should be used in subsequent
 *      calls. Mailbox should be inside {} in order to preserve IMAP mailbox format.
 *      Example:
 *           ns_imap open -mailbox {{localhost/ssl}mail/INBOX} -user vlad -password test -expunge
 *
 *    ns_imap close #s
 *      closes specified mail session
 *
 *    ns_imap reopen #s ?args?
 *      reuse existing session to open another mailbox, optional args are the same
 *      as in open command
 *
 *    ns_imap status #s ?flags?
  *      returns Tcl list with mailbox status
 *      valid flags
 *      OPENTIME - Time mailbox was opened (in seconds from epoch)
 *      LASTACCESS - Last time mailbox was accessed (in seconds from epoch)
 *      USERFLAGS - User flags
 *      MESSAGES - Number of messages in mailbox
 *      RECENT - number of recent messages in mailbox
 *      UNSEEN - number of unseen messages in the mailbox
 *      UIDNEXT - Next UID value to be assigned
 *      UIDVALIDITY - UID validity value
 *      Default (no flags given) will return all values
 *      Example: ns_imap status 1 UNSEEN will return
 *               {Unseen 18}
 *
 *    ns_imap error #s
 *    ns_imap expunge #s
 *
 *    ns_imap append #s mailbox text
 *      appends given mail message into specified mailbox
 *
 *    ns_imap copy #s sequence mailbox
 *      copy message(s) specified by sequence in the form n,n:m into specified mailbox
 *
 *    ns_imap move #s
 *      moves message(s) specified by sequence in the form n,n:m into specified mailbox
 *
 *    ns_imap ping #s
 *      returns 1 if there is new mail
 *
 *    ns_imap check #s
 *      performs internal mailbox checking
 *
 *    ns_imap headers #s msgno ?-array name? ?-flags flags?
 *    ns_imap header #s msgno hdrname ?-flags flags?
 *      fetches the complete, unfiltered RFC 822 format header of the specified
 *      message as a text string and returns it as a Tcl list in the form
 *      { name value name value ... } suitable for using array set command.
 *      If array name is specified, result will be placed into array with the given name
 *      Example:
 *           oss2:nscp 3> ns_imap headers 1 1
 *           Date {Wed, 19 Jan 2000 19:24:39 -0500 (EST)}
 *           Subject {Re: 1.gif}
 *           In-Reply-To <200001171954.OAA15399@host>
 *           Message-Id <Pine.LNX.4.10.10001191922480.2765>
 *           To {John Doe <jdoe@localhost>}
 *           From {Bill Gates <bgates@ms.com>}
 *
 *    ns_imap text #s msgno ?-flags flags?
 *      fetches the non-header text of the
 *      specified message as a text string and returns that text string.  No
 *      attempt is made to segregate individual body parts.
 *      flags may contain one or more options separated by comma:
 *         UID - msg number if UID
 *         PEEK - do not set the \Seen flag if it not already set
 *         INTERNAL - The return string is in "internal" format,
 *       	      without any attempt to canonicalize to CRLF
 *       	      newlines
 *
 *    ns_imap body #s msgno part ?-flags flags? ?-decode? ?-file name? ?-return?
 *      fetches the particular section of the
 *      body of the specified message as a text string and returns that text
 *      string.  The section specification is a string of integers delimited by
 *      period which index into a body part list as per the IMAP4
 *      specification.  Body parts are not decoded by this function.
 *      Flags are the same as in ns_imap text command.
 *      if -decode is specified, body text will be decoded according to
 *      content encoding which is base64 or qprint.
 *      if -file is specified, body contents will be save to the given file
 *      instead of returning it.
 *      if -return is specified, returns body contents into current HTTP connection stream,
 *      performs necessary base64/qprint decoding. Something similar
 *      to ns_return.
 *
 *    ns_imap struct #s msgno ?-flags flags? -array name?
 *    ns_imap bodystruct #s msgno part ?-flags flags? ?-array name?
 *      fetches all the structured information
 *      (envelope, internal date, RFC 822 size, flags, and body structure) for
 *      the given msgno and returns it as a Tcl list in the form { name value name value ... }
 *      suitable for using array set command. ns_imap bodystruct fetches just one particular
 *      message body part.
 *      Flags are the same as in ns_imap text command.
 *      If array name is specified, result will be placed into array with the given name
 *      Example:
 *           host:nscp 5> ns_imap struct 1 26
 *           type multipart encoding 7bit subtype MIXED
 *           body.BOUNDARY ----_=_NextPart_000_01BFD481.52B63550
 *           part1 {type text encoding 7bit subtype PLAIN
 *                  id <Pine.LNX.4.10.10006271849542.1820@thread.crystalballinc.com>
 *                  lines 17 bytes 458 body.CHARSET US-ASCII}
 *
 *    ns_imap m_create #s mailbox
 *      creates new mailbox
 *
 *    ns_imap m_delete #s mailbox
 *      deletes existing mailbox
 *
 *    ns_imap m_rename #s mailbox newname
 *      renames existing mailbox
 *
 *    ns_imap delete #s sequence ?-flags flags?
 *    ns_imap undelete #s sequence ?-flags flags?
 *      marks/unmarks specifies message(s) as deleted
 *      flags may be one or more
 *          UID		The sequence argument contains UIDs instead of
 *       		 sequence numbers
 *          SILENT	Do not update the local cache with the new
 *       		 value of the flags
 *
 *    ns_imap setflags #s sequence flag ?-flags flags?
 *    ns_imap clearflags #s sequence flag ?-flags flags?
 *      adds/clears the specified flag to the flags set for the messages in
 *      the specified sequence.
 *
 *    ns_imap list #s
 *    ns_imap lsub #s
 *      returns a list of mailboxes using reference and pattern.
 *      "*" is a wildcard which matches zero or more
 *      characters; "%" is a variant which does not descend a hierarchy level.
 *      Resulting Tcl list consists from pairs { mailbox attributes .... }
 *      ns_imap lsub returns only subscribed mailboxes.
 *      Example:
 *           oss2:nscp 4> ns_imap list 1 {{localhost}} mail/*
 *           mail/ noselect mail/text {noinferiors unmarked}
 *           mail/private {noinferiors unmarked} mail/trash {noinferiors unmarked}
 *
 *    ns_imap search #s searchCriteria
 *      performs mailbox search and returns found message ids. Supports
 *      IMAP2 search criteria only.
 *      Example:
 *           ns_imap search 1 "FROM john"
 *           ns_imap search 1 "SUBJECT Meeting"
 *
 *    ns_imap subscribe #s mailbox
 *    ns_imap unsusbscribe #s mailbox
 *      adds/removes the given name to/from the subscription list
 *
 *    ns_imap n_msgs #s
 *      returns number of message sin the mailbox
 *
 *    ns_imap n_recent #s
 *      returns number of recent messages in the mailbox
 *
 *    ns_imap uidnext #s
 *      returns next UID to be used

 *    ns_imap uidvalidity #s
 *      returns validity number for the mailbox
 *
 *    ns_imap sort #s criteria reverse ?-flags flags?
 *      returns Tcl list with message numbers according to the given
 *      sort criteria header which can be one of the following:
 *        date arrival from subject to cc size
 *      reverse may be 0 or 1
 *      flags may include:
 *        UID		Return UIDs instead of sequence numbers
 *        NOPREFETCH	Don't prefetch searched messages.
 *
 *    ns_imap uid #s msgno
 *      returns UID for specified message number
 *
 *    ns_imap msgno #s msgno
 *      returns message number for specified UID
 *
 *    ns_imap getflags #s msgno ?-flags ?
 *      returns message flags: D - deleted, R - seen, U - unread, N - new, A - Answered
 *
 *    ns_imap setflags #s msgno flag ?-flags ?
 *      sets messages flags: \\Seen \\Deleted \\Answered
 *
 *    ns_imap clearflags #s msgno flag ?-flags ?
 *      clears messages flags
 *
 *    ns_imap setparam #s name value
 *      stores named value into mail session runtime parameters list,
 *      can be used for keeping session specific information along with
 *      the session, like cookie sesion id
 *
 *      Special names:
 *        session.atclose stores Tcl code/proc to be executed at
 *                        session close.
 *
 *    ns_imap getparam #s name
 *      returns session's value for the given parameter name
 *     Special names:
 *        mailbox - returns canonical mailbox name
 *        mailbox.name - returns just mailbox file name
 *        mailbox.host - returns remote host and options without mailbox name
 *        user - returns name of the logged-in user
 *        authuser - returns authentication user name
 *        host - returns mail host name
 *        password - return session password
 *
 *    ns_imap parsedate datestring
 *      parses date/time string and returns seconds since epoch if date is
 *      correct or empty string if not
 *
 *    ns_imap getquota #s root
 *      returns current quota value
 *
 *    ns_imap setquota #s root size
 *      sets new mailbox storage quota
 *
 *    ns_imap setacl #s mailbox user value
 *      sets acl for the given mailbox and user
 *
 * Authors
 *
 *     Vlad Seryakov vlad@crystalballinc.com
 */
#define USE_TCL8X
#include "ns.h"
#include "c-client.h"
#include "imap4r1.h"
#include "fs.h"
#include <setjmp.h>

#define _VERSION  "3.4"

typedef struct _mailSession {
    struct _mailSession *next, *prev;
    unsigned long id;
    time_t open_time;
    time_t access_time;
    char *mailbox;
    char *user;
    char *passwd;
    char *error;
    Tcl_Interp *interp;
    Tcl_Obj *list;
    Ns_Set *params;
    Ns_Set *headers;
    unsigned long uid;
    MAILSTREAM *stream;
    jmp_buf jmp;
    void *server;
} mailSession;

typedef struct {
    const char *server;
    const char *mailbox;
    const char *user;
    const char *passwd;
    int debug;
    int idle_timeout;
    int gc_interval;
    unsigned long sessionID;
    mailSession *sessions;
    Ns_Mutex mailMutex;
} mailServer;

static int MailCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static char *utf7_decode(char *in, int inlen, int *outlen);
static char *utf7_encode(char *in, int inlen, int *outlen);
static char *strStripHtml(char *str, const char *tags[]);
static char *strLower(char *str);
static void mailGc(void *arg);
static void mm_parseline(ENVELOPE * env, char *hdr, char *data, char *host);
static void mm_getquota(MAILSTREAM * stream, char *qroot, QUOTALIST * qlist);

static Ns_Tls mailTls;
static Ns_TclTraceProc MailInterpInit;

NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;
NS_EXPORT int Ns_ModuleVersion = 1;

/*
 * Load the config parameters, setup the structures
 */

NS_EXPORT int Ns_ModuleInit(const char *server, const char *module)
{
    const char *path;
    static int  first = 0;
    mailServer *serverPtr;

    Ns_Log(Notice, "nsimap module version %s server: %s", _VERSION, server);

    if (!first) {
        first = 1;
        Ns_TlsAlloc(&mailTls, 0);

        mail_link(&imapdriver);
        mail_link(&nntpdriver);
        mail_link(&pop3driver);
        mail_link(&mbxdriver);
        mail_link(&tenexdriver);
        mail_link(&mtxdriver);
        mail_link(&unixdriver);
        mail_link(&dummydriver);
#ifndef _WIN32
        mail_link(&mhdriver);
        mail_link(&mxdriver);
        mail_link(&mmdfdriver);
        mail_link(&newsdriver);
        mail_link(&philedriver);
#else
        auth_link(&auth_gss);
#endif
        auth_link(&auth_md5);
        auth_link(&auth_pla);
        auth_link(&auth_log);
    }
#ifdef HAVE_OPENSSL_EVP_H
    ssl_onceonlyinit();
#endif
    // UW Imap sends USR2
    ns_signal(SIGUSR2, SIG_IGN);
    path = Ns_ConfigGetPath(server, module, NULL);
    serverPtr = ns_calloc(1, sizeof(mailServer));
    serverPtr->server = server;
    serverPtr->mailbox = Ns_ConfigGetValue(path, "mailbox");
    serverPtr->user = Ns_ConfigGetValue(path, "user");
    serverPtr->passwd = Ns_ConfigGetValue(path, "password");
    if (!Ns_ConfigGetInt(path, "idle_timeout", &serverPtr->idle_timeout))
        serverPtr->idle_timeout = 1800;
    if (!Ns_ConfigGetInt(path, "gc_interval", &serverPtr->gc_interval))
        serverPtr->gc_interval = 600;
    Ns_ConfigGetInt(path, "debug", &serverPtr->debug);
    mail_parameters(0, SET_RSHTIMEOUT, 0);
    mail_parameters(0, SET_PARSELINE, (void *)&mm_parseline);
    /* Schedule garbage collection proc for automatic session close/cleanup */
    if (serverPtr->gc_interval > 0) {
        Ns_ScheduleProc(mailGc, serverPtr, 1, serverPtr->gc_interval);
        Ns_Log(Notice, "ns_imap: scheduling GC proc for every %d secs", serverPtr->gc_interval);
    }
    Ns_MutexSetName2(&serverPtr->mailMutex, "nsimap", "imap");
    Ns_TclRegisterTrace(server, MailInterpInit, serverPtr, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

/*
 * Add ns_imap commands to interp.
 */
static int MailInterpInit(Tcl_Interp * interp, const void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_imap", MailCmd, (void *)arg, NULL);
    return NS_OK;
}

// Returns index of the given option
static int tclOption(int objc, Tcl_Obj * CONST objv[], int i, const char *name, int single)
{
    for (; i < objc; i++) {
        if (!strcmp(name, Tcl_GetString(objv[i]))) {
            return single ? i : i + 1 < objc ? i + 1 : -1;
        }
    }
    return -1;
}

/*
 * Returns pointer on existing SNMP session by id
 */

static mailSession *getSession(mailServer * server, unsigned long id)
{
    mailSession *session;

    Ns_MutexLock(&server->mailMutex);
    for (session = server->sessions; session; session = session->next)
        if (session->id == id) {
            break;
        }
    Ns_MutexUnlock(&server->mailMutex);
    return session;
}

/*
 * Frees mail session and all related structures
 */
static void freeSession(mailServer * server, mailSession * session, int lock)
{
    if (session == NULL) {
        return;
    }
    if (server->debug) {
        Ns_Log(Debug, "ns_imap: free: 0x%p: %ld", (void *)session, session->id);
    }

    /* Call atclose Tcl handler */
    if (session->params != NULL) {
        char *proc = Ns_SetGet(session->params, "session.atclose");
        if (proc) {
            Ns_Conn *conn = Ns_GetConn();
            Tcl_Interp *interp = conn ? Ns_GetConnInterp(conn) : 0;
            if (interp)
                Tcl_Eval(interp, proc);
        }
    }
    if (lock)
        Ns_MutexLock(&server->mailMutex);
    if (session->prev)
        session->prev->next = session->next;
    if (session->next)
        session->next->prev = session->prev;
    if (session == server->sessions)
        server->sessions = session->next;
    if (lock)
        Ns_MutexUnlock(&server->mailMutex);
    if (session->stream) {
#ifdef LOCAL
        if (session->stream->dtb && !strcmp(session->stream->dtb->name, "imap"))
            ((IMAPLOCAL *) session->stream->local)->byeseen = 1;
#endif
        mail_close_full(session->stream, 0);
    }
    Ns_SetFree(session->params);
    Ns_SetFree(session->headers);
    ns_free(session->error);
    ns_free(session->user);
    ns_free(session->passwd);
    ns_free(session->mailbox);
    ns_free(session);
}

/*
 * Opens new or reopens existing mail session
 */
static mailSession *openSession(mailServer * server, mailSession * session, int objc, Tcl_Obj * CONST objv[],
                                Tcl_Interp * interp)
{
    int i, flags = 0;
    char *cmd;

    if (!session) {
        session = ns_calloc(1, sizeof(mailSession));
        Ns_MutexLock(&server->mailMutex);
        session->id = ++server->sessionID;
        Ns_MutexUnlock(&server->mailMutex);
        session->interp = interp;
        session->mailbox = ns_strcopy(server->mailbox);
        session->user = ns_strcopy(server->user);
        session->passwd = ns_strcopy(server->passwd);
        session->headers = Ns_SetCreate("headers");
        session->server = server;
    }
    session->uid = 0;
    for (i = 2; i < objc; i++) {
        cmd = Tcl_GetStringFromObj(objv[i], 0);
        if (!strcmp(cmd, "-mailbox")) {
            ns_free(session->mailbox);
            session->mailbox = ns_strcopy(Tcl_GetStringFromObj(objv[++i], 0));
        } else if (!strcmp(cmd, "-reopen")) {
            if (session->stream) {
                mail_close_full(session->stream, 0);
            }
            session->stream = 0;
        } else if (!strcmp(cmd, "-user")) {
            ns_free(session->user);
            session->user = ns_strcopy(Tcl_GetStringFromObj(objv[++i], 0));
        } else if (!strcmp(cmd, "-password")) {
            ns_free(session->passwd);
            session->passwd = ns_strcopy(Tcl_GetStringFromObj(objv[++i], 0));
        } else if (!strcmp(cmd, "-readonly")) {
            flags |= OP_READONLY;
        } else if (!strcmp(cmd, "-debug")) {
            flags |= OP_DEBUG;
        } else if (!strcmp(cmd, "-anonymous")) {
            flags |= OP_ANONYMOUS;
        } else if (!strcmp(cmd, "-halfopen")) {
            flags |= OP_HALFOPEN;
        } else if (!strcmp(cmd, "-expunge")) {
            flags |= OP_EXPUNGE;
        } else if (!strcmp(cmd, "-shortcache")) {
            flags |= OP_SHORTCACHE;
        } else if (!strcmp(cmd, "-novalidatecert")) {
            flags |= NET_NOVALIDATECERT;
        }

    }
    if (server->debug) {
        Ns_Log(Debug, "ns_imap: open: 0x%p: %ld: %s: %s", (void *)session, session->id, session->mailbox, session->user);
    }
    Ns_TlsSet(&mailTls, session);
    if (session->mailbox == NULL
        || !(session->stream = mail_open(session->stream, session->mailbox, flags))
        ) {
        Tcl_AppendResult(interp, "Could not connect to mailbox: ", session->error, 0);
        freeSession(server, session, 1);
        return 0;
    }
    /* Link new session to global session list */
    if (!session->open_time) {
        Ns_MutexLock(&server->mailMutex);
        session->next = server->sessions;
        if (server->sessions) {
            server->sessions->prev = session;
        }
        server->sessions = session;
        session->open_time = session->access_time = time(0);
        Ns_MutexUnlock(&server->mailMutex);
    }
    /* Return session id */
    Tcl_SetObjResult(interp, Tcl_NewIntObj((int) session->id));
    return session;
}

static void mailPair(Tcl_Interp * interp, Tcl_Obj * list, const char *name, const char *svalue, unsigned long lvalue, char *arrayName)
{
    if (!arrayName) {
        Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(name, -1));
        Tcl_ListObjAppendElement(interp, list, svalue ? Tcl_NewStringObj(svalue, -1) : Tcl_NewLongObj((long) lvalue));
    } else {
        Tcl_SetVar2Ex(interp, arrayName, name, svalue ? Tcl_NewStringObj(svalue, -1) : Tcl_NewLongObj((long) lvalue), 0);
    }
}

#if 0
/*
 * seemingly unused functions
 */

static Tcl_Obj *_mailAddress(ADDRESS * addr)
{
    ADDRESS *a;
    char buf[1500] = "";

    for (; addr; addr = addr->next) {
        a = addr->next;
        addr->next = 0;
        if (buf[0]) {
            strcat(buf, ",");
        }
        rfc822_write_address(&buf[strlen(buf)], addr);
        addr->next = a;
        if (strlen(buf) > 512) {
            break;
        }
    }
    return Tcl_NewStringObj(buf, -1);
}

static void mailAddress(Tcl_Interp * interp, Tcl_Obj * list, char *name, ADDRESS * addr, char *arrayName)
{
    if (!arrayName) {
        Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(name, -1));
        Tcl_ListObjAppendElement(interp, list, _mailAddress(addr));
    } else
        Tcl_SetVar2Ex(interp, arrayName, name, _mailAddress(addr), 0);
}
#endif

static void mailFlags(char *str, unsigned long *flags)
{
    if (!*str) return;
    if (strstr(str, "UID"))
        *flags |= FT_UID;
    if (strstr(str, "PEEK"))
        *flags |= FT_PEEK;
    if (strstr(str, "INTERNAL"))
        *flags |= FT_INTERNAL;
    if (strstr(str, "SILENT"))
        *flags |= ST_SILENT;
    if (strstr(str, "PREFETCHTEXT"))
        *flags |= FT_PREFETCHTEXT;
    if (strstr(str, "NOT"))
        *flags |= FT_NOT;
    if (strstr(str, "EXPUNGE"))
        *flags |= CL_EXPUNGE;
    if (strstr(str, "NOPREFETCH"))
        *flags |= SE_NOPREFETCH;
    if (strstr(str, "NOSERVER"))
        *flags |= SO_NOSERVER;
}

static void mailStatus(const char *str, long *flags)
{
    if (!*str) return;
    if (strstr(str, "MESSAGES"))
        *flags |= SA_MESSAGES;
    if (strstr(str, "RECENT"))
        *flags |= SA_RECENT;
    if (strstr(str, "UNSEEN"))
        *flags |= SA_UNSEEN;
    if (strstr(str, "UIDNEXT"))
        *flags |= SA_UIDNEXT;
    if (strstr(str, "UIDVALIDITY"))
        *flags |= SA_UIDVALIDITY;
}

static const char *mailType(int type)
{
    switch (type) {
    case TYPETEXT:
        return "text";
        break;
    case TYPEMULTIPART:
        return "multipart";
        break;
    case TYPEMESSAGE:
        return "message";
        break;
    case TYPEAPPLICATION:
        return "application";
        break;
    case TYPEAUDIO:
        return "audio";
        break;
    case TYPEIMAGE:
        return "image";
        break;
    case TYPEVIDEO:
        return "video";
        break;
    case TYPEMODEL:
        return "model";
        break;
    case TYPEOTHER:
        return "unknown";
        break;
    }
    return "";
}

static char *mailParseFlags(MESSAGECACHE * cache, char *buf)
{
    char *p = buf;

    if (cache->recent && !cache->seen) {
        *p++ = 'N';
    }
    if (!cache->recent && !cache->seen && !cache->deleted) {
        *p++ = 'U';
    }
    if (cache->flagged) {
        *p++ = 'F';
    }
    if (cache->answered) {
        *p++ = 'A';
    }
    if (cache->deleted) {
        *p++ = 'D';
    }
    if (cache->draft) {
        *p++ = 'X';
    }
    *p = 0;
    return buf;
}

static Tcl_Obj *mailStruct(BODY * body, MESSAGECACHE * cache, Tcl_Interp * interp, char *arrayName)
{
    PARAMETER *param;
    char buf[255] = "";
    Tcl_Obj *list = Tcl_NewListObj(0, 0);

    if (!body) {
        return 0;
    }
    /* Message flags */
    if (cache) {
        mailPair(interp, list, "uid", 0, cache->private.uid, arrayName);
        mailParseFlags(cache, buf);
        mailPair(interp, list, "flags", buf, 0, arrayName);
        mailPair(interp, list, "size", 0, (unsigned long) cache->rfc822_size, arrayName);
        mailPair(interp, list, "internaldate.day", 0, (unsigned long) cache->day, arrayName);
        mailPair(interp, list, "internaldate.month", 0, (unsigned long) cache->month, arrayName);
        mailPair(interp, list, "internaldate.year", 0, (unsigned long) (BASEYEAR + cache->year), arrayName);
        mailPair(interp, list, "internaldate.hours", 0, (unsigned long) cache->hours, arrayName);
        mailPair(interp, list, "internaldate.minutes", 0, (unsigned long) cache->minutes, arrayName);
        mailPair(interp, list, "internaldate.seconds", 0, (unsigned long) cache->seconds, arrayName);
        mailPair(interp, list, "internaldate.zoccident", 0, (unsigned long) cache->zoccident, arrayName);
        mailPair(interp, list, "internaldate.zhours", 0, (unsigned long) cache->zhours, arrayName);
        mailPair(interp, list, "internaldate.zminutes", 0, (unsigned long) cache->zminutes, arrayName);
    }
    mailPair(interp, list, "type", (char *) mailType(body->type), 0, arrayName);
    switch (body->encoding) {
    case ENC7BIT:
        mailPair(interp, list, "encoding", "7bit", 0, arrayName);
        break;
    case ENC8BIT:
        mailPair(interp, list, "encoding", "8bit", 0, arrayName);
        break;
    case ENCBINARY:
        mailPair(interp, list, "encoding", "binary", 0, arrayName);
        break;
    case ENCBASE64:
        mailPair(interp, list, "encoding", "base64", 0, arrayName);
        break;
    case ENCQUOTEDPRINTABLE:
        mailPair(interp, list, "encoding", "qprint", 0, arrayName);
        break;
    case ENCOTHER:
        mailPair(interp, list, "encoding", "unknown", 0, arrayName);
        break;
    }
    mailPair(interp, list, "subtype", body->subtype ? body->subtype : "unknown", 0, arrayName);
    if (body->description) {
        mailPair(interp, list, "description", body->description, 0, arrayName);
    }
    if (body->id) {
        mailPair(interp, list, "id", body->id, 0, arrayName);
    }
    if (body->size.lines) {
        mailPair(interp, list, "lines", 0, body->size.lines, arrayName);
    }
    if (body->size.bytes) {
        mailPair(interp, list, "bytes", 0, body->size.bytes, arrayName);
    }
    if (body->disposition.type) {
        mailPair(interp, list, "disposition", body->disposition.type, 0, arrayName);
    }
    for (param = body->disposition.parameter; param; param = param->next) {
        snprintf(buf, 254, "disposition.%s", param->attribute);
        mailPair(interp, list, strLower(buf), param->value, 0, arrayName);
    }
    for (param = body->parameter; param; param = param->next) {
        snprintf(buf, 254, "body.%s", param->attribute);
        mailPair(interp, list, strLower(buf), param->value, 0, arrayName);
    }
    /* multipart message */
    if (body->type == TYPEMULTIPART) {
        unsigned int i = 0;
        PART *part;
        for (part = body->nested.part; part; part = part->next) {
            sprintf(buf, "part.%d", ++i);
            if (!arrayName) {
                Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(buf, -1));
                Tcl_ListObjAppendElement(interp, list, mailStruct(&part->body, 0, interp, 0));
            } else
                Tcl_SetVar2Ex(interp, arrayName, buf, mailStruct(&part->body, 0, interp, 0), 0);
        }
        mailPair(interp, list, "part.count", 0, i, arrayName);
    }
    /* encapsulated message */
    if ((body->type == TYPEMESSAGE) && (!strcasecmp(body->subtype, "rfc822"))) {
        if (!arrayName) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj("message", -1));
            Tcl_ListObjAppendElement(interp, list, mailStruct(body->nested.msg->body, 0, interp, 0));
        } else
            Tcl_SetVar2Ex(interp, arrayName, "message", mailStruct(body->nested.msg->body, 0, interp, 0), 0);
    }
    return list;
}

/* Parse and cache messages headers */
static int mailHeaders(mailSession * session, unsigned long msg)
{
    ENVELOPE *en;
    MESSAGECACHE *elt;
    char *hdr, buf[32];

    hdr = mail_fetchheader(session->stream, msg);
    elt = mail_elt(session->stream, msg);
    if (session->error || !elt || !hdr) {
        Tcl_AppendResult(session->interp, session->error, 0);
        return -1;
    }
    session->uid = mail_uid(session->stream, msg);
    Ns_SetTrunc(session->headers, 0);
    rfc822_parse_msg(&en, 0, hdr, strlen(hdr), 0, (char *)"UNKNOWN", 0);
    mail_free_envelope(&en);
    sprintf(buf, "%lu", elt->rfc822_size);
    Ns_SetPut(session->headers, "X-Message-Size", buf);
    mailParseFlags(elt, buf);
    Ns_SetPut(session->headers, "X-Message-Flags", buf);
    sprintf(buf, "%lu", session->uid);
    Ns_SetPut(session->headers, "X-Message-UID", buf);
    return 0;
}

// Garbage collection routine, closes expired sessions
static void mailGc(void *arg)
{
    mailServer *server = arg;
    mailSession *session;
    time_t now = time(0);
    char *str;
    int idle_timeout;

    Ns_MutexLock(&server->mailMutex);
    for (session = server->sessions; session;) {
        if (session->params && (str = Ns_SetGet(session->params, "session.idle_timeout")))
            idle_timeout = atoi(str);
        else
            idle_timeout = server->idle_timeout;
        if (now - session->access_time > idle_timeout) {
            mailSession *next = session->next;
            Ns_Log(Notice, "ns_imap: GC: inactive session %ld: %s", session->id, session->stream->mailbox);
            Ns_TlsSet(&mailTls, session);
            /* In case of panic we will be thrown here again */
            if (!setjmp(session->jmp)) {
                freeSession(server, session, 0);
            }
            session = next;
            continue;
        }
        session = session->next;
    }
    Ns_MutexUnlock(&server->mailMutex);
}

// Parse flags and convert message number if necessary
static unsigned long mailParseMsgFlags(mailSession *session, unsigned long msg, unsigned long *flags, int objc, Tcl_Obj * CONST objv[])
{
    int index;

    if (objc > 4) {
        if ((index = tclOption(objc, objv, 4, "-flags", 0)) > 0) {
            mailFlags(Tcl_GetString(objv[index]), flags);
        }
    }
    if (msg > 0 && *flags & FT_UID) {
        if ((msg = mail_msgno(session->stream, msg))) {
            *flags &= (unsigned long)~FT_UID;
        }
    }
    return msg;
}

/*
 *  ns_imap implementation
 */

static int MailCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    int cmd, index = 0;
    unsigned int num;
    mailSession *session = 0;
    mailServer *server = arg;
    unsigned long msg, flags = 0u;

    enum commands {
        cmdGc, cmdSessions, cmdDecode, cmdEncode, cmdParseDate, cmdStripHtml,
        cmdOpen,
        cmdClose, cmdReopen, cmdStatus, cmdHeaders, cmdText, cmdBody, cmdError,
        cmdExpunge, cmdAppend, cmdCopy, cmdMove, cmdPing, cmdSearch,
        cmdCheck, cmdStruct, cmdMCreate, cmdMDelete, cmdMRename, cmdDelete,
        cmdUndelete, cmdGetFlags, cmdSetFlags, cmdClearFlags, cmdList, cmdLsub, cmdSubscribe,
        cmdUnsubscribe, cmdNmsgs, cmdNrecent, cmdSort, cmdBodyStruct, cmdUid,
        cmdHeader, cmdGetParam, cmdSetParam, cmdSetQuota, cmdGetQuota, cmdSetAcl,
        cmdUidNext, cmdUidValidity, cmdMsgno
    };

    static const char *sCmd[] = {
        "gc", "sessions", "decode", "encode", "parsedate", "striphtml",
        "open",
        "close", "reopen", "status", "headers", "text", "body", "error",
        "expunge", "append", "copy", "move", "ping", "search",
        "check", "struct", "m_create", "m_delete", "m_rename", "delete",
        "undelete", "getflags", "setflags", "clearflags", "list", "lsub", "subscribe",
        "unsubscribe", "n_msgs", "n_recent", "sort", "bodystruct", "uid",
        "header", "getparam", "setparam", "setquota", "getquota", "setacl",
        "uidnext", "uidvalidity", "msgno",
        0
    };

    if (objc < 2) {
        Tcl_AppendResult(interp, "wrong # args: should be ns_imap command ?args ...?", 0);
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK)
        return TCL_ERROR;

    /* Session related commands */
    if (cmd > cmdOpen) {
        if (objc < 3) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap command #s ?args ...?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetIntFromObj(interp, objv[2], (int*)&num) != TCL_OK) {
            return TCL_ERROR;
        }
        if (!(session = getSession(server, num))) {
            Tcl_AppendResult(interp, "Invalid or expired mail session", 0);
            return TCL_ERROR;
        }
        /* Remember mail session */
        Ns_TlsSet(&mailTls, session);
        session->interp = interp;
        session->access_time = time(0);
        if (cmd != cmdError) {
            ns_free(session->error), session->error = 0;
        }
        /* In case of panic we will be thrown here again */
        if (setjmp(session->jmp)) {
            return TCL_ERROR;
        }
    }

    switch (cmd) {
    case cmdGc:
        mailGc(0);
        break;

    case cmdSessions:{
        // List opened sessions
        Tcl_Obj *list = Tcl_NewListObj(0, 0);
        Ns_MutexLock(&server->mailMutex);
        for (session = server->sessions; session; session = session->next) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj((int) session->id));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj((int) session->open_time));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj((int) session->access_time));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(session->stream->mailbox, -1));
        }
        Ns_MutexUnlock(&server->mailMutex);
        Tcl_SetObjResult(interp, list);
        return TCL_OK;
    }

    case cmdStripHtml:{
        char              *data;
        static const char *tags[] = { "BODY", "FRAME", "FRAMESET", "HEAD", "TITLE",
            "META", "DIV", "OBJECT", "EMBED", "BASE", 0
        };

        if (objc < 3) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " text ?tags?", 0);
            return TCL_ERROR;
        }
        data = strStripHtml(Tcl_GetString(objv[2]), tags);
        Tcl_SetResult(interp, data, (Tcl_FreeProc *) ns_free);
        break;
    }

    case cmdParseDate:{
        MESSAGECACHE msgCache;

        if (objc < 3) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " datestring", 0);
            return TCL_ERROR;
        }
        if (mail_parse_date(&msgCache, (unsigned char*)Tcl_GetStringFromObj(objv[2], 0))) {
            struct tm lt;
            time_t    t;

            lt.tm_min = msgCache.minutes;
            lt.tm_sec = msgCache.seconds;
            lt.tm_hour = msgCache.hours;
            lt.tm_mday = msgCache.day;
            lt.tm_mon = msgCache.month - 1;
            lt.tm_year = BASEYEAR + msgCache.year - 1900;
            if ((t = mktime(&lt)) > 0) {
                char buf[32] = "";

                sprintf(buf, "%lu", t);
                Tcl_AppendResult(interp, buf, 0);
            }
        }
        break;
    }

    case cmdDecode:{
        // Decode text into plain 8bit string
        char         *data;
        void         *vdata = NULL;
        int           len = 0;
        unsigned long llen;

        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " type text", 0);
            return TCL_ERROR;
        }

        data = (char *) Tcl_GetByteArrayFromObj(objv[3], (int *) &len);
        // Decode BASE64 encoded text */
        if (!strcmp(Tcl_GetStringFromObj(objv[2], 0), "base64")) {
            vdata = (char *) rfc822_base64((unsigned char*)data, (unsigned long)len, &llen);
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(vdata, (int) llen));
            fs_give(&vdata);
            return TCL_OK;
        } else
            // Convert a quoted-printable string to an 8-bit string */
        if (!strcmp(Tcl_GetStringFromObj(objv[2], 0), "qprint")) {
            vdata = (char *) rfc822_qprint((unsigned char*)data, (unsigned long)len, &llen);
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(vdata, (int) llen));
            fs_give(&vdata);
            return TCL_OK;
        } else
            // Convert a UTF7 an 8-bit string */
        if (!strcmp(Tcl_GetStringFromObj(objv[2], 0), "utf7")) {
            if ((data = utf7_decode(data, len, &len))) {
                Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char*)data, (int) len));
                ns_free(vdata);
                return TCL_OK;
            }
        }
        Tcl_SetObjResult(interp, objv[3]);
        return TCL_OK;
    }

    case cmdEncode:{
        // Encode plain 8bit string
        void *vdata;
        char *data;
        int len = 0;
        unsigned long llen;
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " type text", 0);
            return TCL_ERROR;
        }
        data = (char *) Tcl_GetByteArrayFromObj(objv[3], (int *) &len);
        // Convert an 8bit string to a quoted printable string */
        if (!strcmp(Tcl_GetStringFromObj(objv[2], 0), "qprint")) {
            vdata = (char *) rfc822_8bit((unsigned char*)data, (unsigned long)len, &llen);
            Tcl_SetObjResult(interp, Tcl_NewStringObj(vdata, (int) llen));
            fs_give(&vdata);
            return TCL_OK;
        } else
            // Convert an 8bit string to a base64 string */
        if (!strcmp(Tcl_GetStringFromObj(objv[2], 0), "base64")) {
            vdata = (char *) rfc822_binary((unsigned char*)data, (unsigned long)len, &llen);
            Tcl_SetObjResult(interp, Tcl_NewStringObj(vdata, (int) llen));
            fs_give(&vdata);
            return TCL_OK;
        } else
            // Convert a 8-bit string into UTF7 */
        if (!strcmp(Tcl_GetStringFromObj(objv[2], 0), "utf7")) {
            if ((data = utf7_encode(data, len, &len))) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj(data, (int) len));
                ns_free(data);
                return TCL_OK;
            }
        }
        Tcl_SetObjResult(interp, objv[3]);
        return TCL_OK;
    }

    case cmdOpen:
        // Open a stream to a mailbox
        if (!openSession(server, 0, objc, objv, interp)) {
            return TCL_ERROR;
        }
        return TCL_OK;

    case cmdReopen:
        // Reopen a stream to a new mailbox
        if (!openSession(server, session, objc, objv, interp)) {
            return TCL_ERROR;
        }
        break;

    case cmdError:
        // Return last error message
        Tcl_AppendResult(interp, session->error, 0);
        break;

    case cmdExpunge:
        // Permanently delete all messages marked for deletion
        session->uid = 0;
        mail_expunge(session->stream);
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdUid:
        // Returns the UID for the given message sequence number
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s msgno", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long *) &msg) != TCL_OK || msg <= 0 || msg > session->stream->nmsgs) {
            Tcl_AppendResult(interp, "Invalid message number", 0);
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj((int) mail_uid(session->stream, msg)));
        break;

    case cmdMsgno:
        // Returns the message number by given message UID
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s uid", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long *) &msg) != TCL_OK) {
            Tcl_AppendResult(interp, "Invalid message number", 0);
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj((int) mail_msgno(session->stream, msg)));
        break;

    case cmdGetParam:{
        char *value = 0, *name, buf[255];
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s name", 0);
            return TCL_ERROR;
        }
        name = Tcl_GetString(objv[3]);
        if (session->params) {
            value = Ns_SetGet(session->params, name);
        }
        if (!value && session->stream->mailbox) {
            NETMBX mb;
            if (!mail_valid_net_parse(session->stream->mailbox, &mb))
                break;
            if (!strcmp(name, "user"))
                value = mb.user;
            else if (!strcmp(name, "password"))
                value = session->passwd;
            else if (!strcmp(name, "authuser"))
                value = mb.authuser;
            else if (!strcmp(name, "mailbox"))
                value = session->stream->mailbox;
            else if (!strcmp(name, "mailbox.name"))
                value = mb.mailbox;
            else if (!strcmp(name, "host"))
                value = mb.host;
            else if (!strcmp(name, "mailbox.host")) {
                snprintf(buf, 254, "%s", session->stream->mailbox);
                if ((name = strchr(buf, '}')))
                    *(name + 1) = 0;
                value = buf;
            }
        }
        Tcl_AppendResult(interp, value, 0);
        break;
    }

    case cmdSetParam:{
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s name value", 0);
            return TCL_ERROR;
        }
        if (!session->params) {
            session->params = Ns_SetCreate("params");
        }
        if ((index = Ns_SetFind(session->params, Tcl_GetStringFromObj(objv[3], 0))) > -1) {
            Ns_SetPutValue(session->params, (size_t)index, Tcl_GetStringFromObj(objv[4], 0));
        } else {
            Ns_SetPut(session->params, Tcl_GetStringFromObj(objv[3], 0), Tcl_GetStringFromObj(objv[4], 0));
        }
        break;
    }

    case cmdAppend:{
        // Append a new message to a specified mailbox
        unsigned int len;
        char *text;
        STRING st;
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s mailbox text ?-flags flags?", 0);
            return TCL_ERROR;
        }
        index = tclOption(objc, objv, 5, "-flags", 0);

        session->uid = 0;
        text = Tcl_GetStringFromObj(objv[4], (int*)&len);
        INIT(&st, mail_string, text, len);
        if (!mail_append_full(session->stream, Tcl_GetString(objv[3]), index > 0 ? Tcl_GetString(objv[index]) : 0, 0, &st)) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;
    }

    case cmdCopy:
        // Copy specified message to a mailbox
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s sequence mailbox ?-flags flags?", 0);
            return TCL_ERROR;
        }
        mailParseMsgFlags(session, msg, &flags, objc, objv);

        if (!mail_copy_full(session->stream, Tcl_GetString(objv[3]), Tcl_GetString(objv[4]), (long)flags)) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdMove:
        // Move specified message to another mailbox
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s sequence mailbox ?-flags flags?", 0);
            return TCL_ERROR;
        }
        mailParseMsgFlags(session, msg, &flags, objc, objv);

        session->uid = 0;
        if (!mail_copy_full(session->stream, Tcl_GetString(objv[3]), Tcl_GetString(objv[4]), (long)(flags | CP_MOVE))) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdPing:
        // Check if the stream is still active
        if (!session->stream) {
            break;
        }
        Tcl_SetObjResult(interp, Tcl_NewLongObj(mail_ping(session->stream)));
        break;

    case cmdCheck:
        // Perform internal stream/mailbox checkings
        mail_check(session->stream);
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdHeaders:{
        // Read message headers
        char *array = 0;
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s msgno ?-array name? ?-flags flags?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long*)&msg) != TCL_OK) {
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        if (mailHeaders(session, msg)) {
            return TCL_ERROR;
        }
        if ((index = tclOption(objc, objv, 4, "-array", 0)) > 0) {
            array = Tcl_GetString(objv[index]);
        }
        session->list = Tcl_NewListObj(0, 0);
        for (num = 0; num < Ns_SetSize(session->headers); num++) {
            mailPair(interp, session->list, Ns_SetKey(session->headers, num), Ns_SetValue(session->headers, num), 0, array);
        }
        Tcl_SetObjResult(interp, session->list);
        break;
    }

    case cmdHeader:{
        // Returns specified header value
        char *hdr;
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s msgno hdrname ?-flags flags?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long*)&msg) != TCL_OK) {
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        if (mailHeaders(session, msg)) {
            return TCL_ERROR;
        }
        if ((hdr = Ns_SetIGet(session->headers, Tcl_GetString(objv[4])))) {
            Tcl_AppendResult(interp, hdr, 0);
        }
        break;
    }

    case cmdText:{
        // Read the message text
        char *text;
        unsigned long len;
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s msgno ?-flags flags?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long*)&msg) != TCL_OK) {
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        text = mail_fetchtext_full(session->stream, msg, &len, (int) flags);
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char*)text, (int) len));
        break;
    }

    case cmdBody:{
        // Read the body part
        BODY *body = 0;
        PARAMETER *filename;
        void *data = 0;
        char *text, *fname = 0;
        unsigned long len, decode = 0, mode = 0;

        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s msgno part ?-flags flags? ?-decode? ?-file name? ?-return?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long*)&msg) != TCL_OK) {
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        if (objc > 5) {
            if ((index = tclOption(objc, objv, 5, "-decode", 1)) > 0) {
                decode = 1;
            }
            if ((index = tclOption(objc, objv, 5, "-return", 1)) > 0) {
                mode = 1;
            }
            if ((index = tclOption(objc, objv, 5, "-file", 0)) > 0) {
                mode = 2;
                fname = Tcl_GetStringFromObj(objv[index], 0);
            }
        }

        text = mail_fetchbody_full(session->stream, msg, Tcl_GetString(objv[4]), &len, (int) flags);
        if (text) {
            body = mail_body(session->stream, msg, (unsigned char*)Tcl_GetString(objv[4]));
        }
        if (!text || !body || session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        if (decode || mode) {
            switch (body->encoding) {
            case ENCBASE64:
                text = data = (char *) rfc822_base64((unsigned char*)text, (unsigned long)len, &len);
                break;
            case ENCQUOTEDPRINTABLE:
                text = data = (char *) rfc822_qprint((unsigned char*)text, (unsigned long)len, &len);
            }
        }
        // Discover attachment file name
        for (filename = body->disposition.parameter; filename; filename = filename->next) {
            if (!strcasecmp(filename->attribute, "filename"))
                break;
        }
        switch (mode) {
        case 1:{
            char type[512];
            snprintf(type, sizeof(type), "%s/%s", mailType(body->type), body->subtype);
            strLower(type);
            // Use aolserver mime types
            if ((strstr(type, "unknown") || strstr(type, "octet-stream")) && filename) {
                snprintf(type, sizeof(type), "%s", Ns_GetMimeType(filename->value));
            }
            if (filename && sizeof(type) - strlen(type) > strlen(filename->value) + 3)
                sprintf(&type[strlen(type)], "; %s", filename->value);
            Ns_ConnReturnData(Ns_GetConn(), 200, text, (int) len, type);
            break;
        }

        case 2:
            Ns_Log(Debug, "nsimap: body: %s, %s", fname, filename ? filename->value : 0);
            if (*fname == 0 && filename)
                fname = filename->value;
            if ((index = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1) {
                Tcl_AppendResult(interp, "Unable to create file:", fname, ", ", strerror(errno), 0);
                return TCL_ERROR;
            }
            write(index, text, (int) len);
            close(index);
            break;
        default:
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char*)text, (int) len));
        }
        if (data)
            fs_give(&data);
        break;
    }

    case cmdBodyStruct:{
        // Read the structure of a specified body section of a specific message
        BODY *body;
        char *array = 0;
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s msgno part ?-array name? ?-flags flags?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long*)&msg) != TCL_OK) {
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        if ((index = tclOption(objc, objv, 5, "-array", 0)) > 0) {
            array = Tcl_GetString(objv[index]);
        }

        if ((body = mail_body(session->stream, msg, (unsigned char*)Tcl_GetStringFromObj(objv[4], 0)))) {
            Tcl_SetObjResult(interp, mailStruct(body, 0, interp, array));
        }
        break;
    }

    case cmdStruct:{
        // Read the whole message
        BODY *body;
        Tcl_Obj *obj;
        char *array = 0;
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s msgno ?-flags flags? ?-array name?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long*)&msg) != TCL_OK) {
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);
        if ((index = tclOption(objc, objv, 4, "-array", 0)) > 0) {
            array = Tcl_GetString(objv[index]);
        }

        if (!mail_fetchstructure_full(session->stream, msg, &body, (int) flags) || !body) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        obj = mailStruct(body, mail_elt(session->stream, msg), interp, array);
        mailPair(interp, obj, "msgno", 0, msg, array);
        Tcl_SetObjResult(interp, obj);
        break;
    }

    case cmdMCreate:
        // Create a new mailbox
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s mailbox", 0);
            return TCL_ERROR;
        }
        if (!mail_create(session->stream, Tcl_GetString(objv[3]))) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdMDelete:
        // Delete a mailbox
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s mailbox", 0);
            return TCL_ERROR;
        }
        if (!mail_delete(session->stream, Tcl_GetString(objv[3]))) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdMRename:
        // Rename a mailbox
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s mailbox newname", 0);
            return TCL_ERROR;
        }
        if (!mail_rename(session->stream, Tcl_GetString(objv[3]), Tcl_GetString(objv[4]))) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdDelete:
        // Mark a message(s) for deletion

        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s sequence ?-flags flags?", 0);
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);
        session->uid = 0;

        mail_setflag_full(session->stream, Tcl_GetString(objv[3]), (char*)"\\DELETED", (long)flags);
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;


    case cmdUndelete:
        // Remove the delete flag from a message(s)

        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s sequence ?-flags flags?", 0);
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        mail_clearflag_full(session->stream, Tcl_GetString(objv[3]), (char*)"\\DELETED", (long)flags);
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;


    case cmdGetFlags: {
        // Returns message flags
        char buf[16] = "";
        MESSAGECACHE *elt;

        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s msgno ?-flags flags?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], (long*)&msg) != TCL_OK) {
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        mail_fetch_flags(session->stream, Tcl_GetString(objv[3]), (long)flags);
        if ((elt = mail_elt(session->stream, msg))) {
            mailParseFlags(elt, buf);
        }
        Tcl_AppendResult(interp, buf, NULL);
        break;
    }

    case cmdSetFlags:
        // Set message flags

        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s sequence flag ?-flags flags?", 0);
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        mail_setflag_full(session->stream, Tcl_GetString(objv[3]), Tcl_GetString(objv[4]), (long)flags);
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdClearFlags:
        // Clear message flags

        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s sequence flag ?-flags flags?", 0);
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, (unsigned long*)&flags, objc, objv);

        mail_clearflag_full(session->stream, Tcl_GetString(objv[3]), Tcl_GetString(objv[4]), (long)flags);
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdLsub:
        // Return a list of subscribed mailboxes
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s ref pattern", 0);
            return TCL_ERROR;
        }
        session->list = Tcl_NewListObj(0, 0);
        mail_lsub(session->stream, Tcl_GetString(objv[3]), Tcl_GetString(objv[4]));
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, session->list);
        break;

    case cmdSort:{
        // Sort an array of message headers
        SORTPGM            pgm;
        void              *vdata;
        SEARCHPGM         *spg = 0;
        unsigned long     *id, *ids;
        static const char *sSort[] = { "date", "arrival", "from", "subject", "to", "cc", "size", 0 };
        static short       iSort[] = { SORTDATE, SORTARRIVAL, SORTFROM, SORTSUBJECT, SORTTO, SORTCC, SORTSIZE };

        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s criteria reverse ?-flags flags?", 0);
            return TCL_ERROR;
        }
        if (Tcl_GetIndexFromObj(interp, objv[3], sSort, "option", TCL_EXACT, (int*)&num) != TCL_OK) {
            return TCL_ERROR;
        }
        msg = mailParseMsgFlags(session, msg, &flags, objc, objv);

        memset(&pgm, 0, sizeof(pgm));
        pgm.function = iSort[num];
        if (Tcl_GetIntFromObj(0, objv[4], &index) == TCL_OK) {
            pgm.reverse = index ? 1 : 0;
        }
        spg = mail_newsearchpgm();
        if ((vdata = ids = mail_sort(session->stream, 0, spg, &pgm, (long)flags))) {
            session->list = Tcl_NewListObj(0, 0);
            for (id = ids; *id; id++) {
                Tcl_ListObjAppendElement(interp, session->list, Tcl_NewIntObj((int) *id));
            }
            fs_give(&vdata);
            Tcl_SetObjResult(interp, session->list);
        }
        mail_free_searchpgm(&spg);
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;
    }

    case cmdSearch:{
        // Search message headers
        SEARCHPGM    *crit = 0;
        unsigned long id;

        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s criteria", 0);
            return TCL_ERROR;
        }
        if (!session->stream->nmsgs) {
            break;
        }
        if (!(crit = mail_criteria(Tcl_GetString(objv[3])))) {
            break;
        }
        if (mail_search_full(session->stream, 0, crit, SE_FREE)) {
            session->list = Tcl_NewListObj(0, 0);
            for (id = 1; id <= session->stream->nmsgs; id++) {
                if (mail_elt(session->stream, id)->searched) {
                    Tcl_ListObjAppendElement(interp, session->list, Tcl_NewWideIntObj((Tcl_WideInt)id));
                }
            }
            Tcl_SetObjResult(interp, session->list);
        }
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;
    }

    case cmdList:
        // Read the list of mailboxes using optional pattern and substring
        if (objc < 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s ref pattern ?substr?", 0);
            return TCL_ERROR;
        }
        session->list = Tcl_NewListObj(0, 0);
        if (objc == 5) {
            mail_list(session->stream, Tcl_GetStringFromObj(objv[3], 0), Tcl_GetStringFromObj(objv[4], 0));
        } else {
            mail_scan(session->stream, Tcl_GetStringFromObj(objv[3], 0), Tcl_GetStringFromObj(objv[4], 0), Tcl_GetStringFromObj(objv[5], 0));
        }
        if (session->error) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, session->list);
        break;

    case cmdNmsgs:
        // Gives the number of messages in the current mailbox
        Tcl_SetObjResult(interp, Tcl_NewIntObj((int) session->stream->nmsgs));
        break;

    case cmdNrecent:
        // Gives the number of recent messages in current mailbox
        Tcl_SetObjResult(interp, Tcl_NewIntObj((int) session->stream->recent));
        break;

    case cmdUidNext:
        // Gives the next uid to be used
        Tcl_SetObjResult(interp, Tcl_NewIntObj((int) session->stream->uid_last + 1));
        break;

    case cmdUidValidity:
        // Gives the uid validity number
        Tcl_SetObjResult(interp, Tcl_NewIntObj((int) session->stream->uid_validity));
        break;

    case cmdSubscribe:
        // Subscribe to a mailbox
        if (objc != 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s mailbox", 0);
            return TCL_ERROR;
        }
        if (!mail_subscribe(session->stream, Tcl_GetStringFromObj(objv[3], 0))) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdUnsubscribe:
        // Unsubscribe from a mailbox
        if (objc != 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s mailbox", 0);
            return TCL_ERROR;
        }
        if (!mail_unsubscribe(session->stream, Tcl_GetStringFromObj(objv[3], 0))) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;

    case cmdStatus:{
        long        lflags = 0;
        const char *status_flags;

        // Get status info from a mailbox
        if (objc != 4) {
            status_flags = "OPENTIME LASTACCESS USERFLAGS MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY";
        } else {
            status_flags = Tcl_GetString(objv[3]);
        }
        session->list = Tcl_NewListObj(0, 0);
        if (strstr(status_flags, "OPENTIME")) {
            mailPair(interp, session->list, "Open Time", 0, (unsigned long)session->open_time, 0);
        }
        if (strstr(status_flags, "LASTACCESS")) {
            mailPair(interp, session->list, "Last Access Time", 0, (unsigned long)session->access_time, 0);
        }
        if (session->stream->mailbox) {
            if (strstr(status_flags, "MAILBOX")) {
                mailPair(interp, session->list, "Mailbox", session->stream->mailbox, 0, 0);
            }
        }
        mailStatus(status_flags, &lflags);
        mail_status(session->stream, session->stream->mailbox, lflags);
        if (strstr(status_flags, "USERFLAGS")) {
            for (num = 0; num < NUSERFLAGS && session->stream->user_flags[num]; ++num) {
                Tcl_ListObjAppendElement(interp, session->list, Tcl_NewStringObj(session->stream->user_flags[num], -1));
            }
        }
        Tcl_SetObjResult(interp, session->list);
        break;
    }

    case cmdSetQuota:{
        // Set quota
        STRINGLIST limits;
        if (objc != 5) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s root size", 0);
            return TCL_ERROR;
        }
        limits.next = 0;
        limits.text.data = (unsigned char*)"STORAGE";
        if (Tcl_GetLongFromObj(interp, objv[4], (long*)&limits.text.size) != TCL_OK) {
            return TCL_ERROR;
        }
        if (!imap_setquota(session->stream, Tcl_GetStringFromObj(objv[3], 0), &limits)) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;
    }

    case cmdGetQuota:{
        // Current quota
        if (objc != 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s root", 0);
            return TCL_ERROR;
        }
        session->list = Tcl_NewListObj(0, 0);
        mail_parameters(NIL, SET_QUOTA, (void *) mm_getquota);
        if (!imap_getquota(session->stream, Tcl_GetStringFromObj(objv[3], 0))) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, session->list);
        break;
    }

    case cmdSetAcl:{
        // Set ACL
        if (objc != 6) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_imap ", sCmd[cmd], " #s mailbox id right", 0);
            return TCL_ERROR;
        }
        if (!imap_setacl(session->stream, Tcl_GetStringFromObj(objv[3], 0), Tcl_GetStringFromObj(objv[4], 0), Tcl_GetStringFromObj(objv[5], 0))) {
            Tcl_AppendResult(interp, session->error, 0);
            return TCL_ERROR;
        }
        break;
    }

    case cmdClose:
        // Close a stream
        freeSession(server, session, 1);
        break;
    }
    return TCL_OK;
}

/* Interfaces to C-client */
void mm_searched(MAILSTREAM * UNUSED(stream), unsigned long UNUSED(number))
{
}

void mm_exists(MAILSTREAM * UNUSED(stream), unsigned long UNUSED(number))
{
}

void mm_expunged(MAILSTREAM * UNUSED(stream), unsigned long UNUSED(number))
{
}

void mm_flags(MAILSTREAM * UNUSED(stream), unsigned long UNUSED(number))
{
}

void mm_notify(MAILSTREAM * UNUSED(stream), char *string, long errflg)
{
    mm_log(string, errflg);
}

void mm_list(MAILSTREAM * UNUSED(stream), int UNUSED(delimiter), char *mailbox, long attrs)
{
    mailSession *session = Ns_TlsGet(&mailTls);
    Tcl_Obj     *attr;
    char        *name;

    if (!session) return;
    attr = Tcl_NewListObj(0, 0);
    name = strchr(mailbox, '}');

    if (name) {
        name++;
    } else {
        name = mailbox;
    }
    Tcl_ListObjAppendElement(session->interp, session->list, Tcl_NewStringObj(name, -1));
    if (attrs & LATT_NOINFERIORS) {
        Tcl_ListObjAppendElement(session->interp, attr, Tcl_NewStringObj("noinferiors", -1));
    }
    if (attrs & LATT_NOSELECT) {
        Tcl_ListObjAppendElement(session->interp, attr, Tcl_NewStringObj("noselect", -1));
    }
    if (attrs & LATT_MARKED) {
        Tcl_ListObjAppendElement(session->interp, attr, Tcl_NewStringObj("marked", -1));
    }
    if (attrs & LATT_UNMARKED) {
        Tcl_ListObjAppendElement(session->interp, attr, Tcl_NewStringObj("unmarked", -1));
    }
    Tcl_ListObjAppendElement(session->interp, session->list, attr);
}

void mm_lsub(MAILSTREAM * stream, int delimiter, char *mailbox, long attrs)
{
    mm_list(stream, delimiter, mailbox, attrs);
}

void mm_status(MAILSTREAM * UNUSED(stream), char *UNUSED(mailbox), MAILSTATUS * status)
{
    mailSession *session = Ns_TlsGet(&mailTls);
    if (!session) return;
    if (status->flags & SA_MESSAGES) {
        mailPair(session->interp, session->list, "Messages", 0, status->messages, 0);
    }
    if (status->flags & SA_RECENT) {
        mailPair(session->interp, session->list, "Recent", 0, status->recent, 0);
    }
    if (status->flags & SA_UNSEEN) {
        mailPair(session->interp, session->list, "Unseen", 0, status->unseen, 0);
    }
    if (status->flags & SA_UIDNEXT) {
        mailPair(session->interp, session->list, "Uidnext", 0, status->uidnext, 0);
    }
    if (status->flags & SA_UIDVALIDITY) {
        mailPair(session->interp, session->list, "Uidvalidity", 0, status->uidvalidity, 0);
    }
}

void mm_log(char *string, long errflg)
{
    mailSession *session = Ns_TlsGet(&mailTls);
    if (!session) return;
    switch (errflg) {
    case PARSE:
    case WARN:
        Ns_Log(Notice, "ns_imap: %s", string);
        break;
    case ERROR:{
            ns_free(session->error);
            session->error = ns_strcopy(string);
            Ns_Log(Error, "ns_imap: [%ld]: %s", session->id, string);
            break;
        }
    default:{
            if (!((mailServer *) (session->server))->debug)
                break;
            Ns_Log(Debug, "ns_imap: %s", string);
        }
    }
}

void mm_dlog(char *string)
{
    mm_log(string, 0);
}

void mm_login(NETMBX * mb, char *user, char *passwd, long UNUSED(trial))
{
    mailSession *session = Ns_TlsGet(&mailTls);

    if (!session) return;
    memset(user, 0, MAILTMPLEN);
    memset(passwd, 0, MAILTMPLEN);
    strncpy(user, session->user ? session->user : *mb->user ? mb->user : "", MAILTMPLEN);
    strncpy(passwd, session->passwd ? session->passwd : "", MAILTMPLEN);
}

void mm_critical(MAILSTREAM * UNUSED(stream))
{
}

void mm_nocritical(MAILSTREAM * UNUSED(stream))
{
}

long mm_diskerror(MAILSTREAM * UNUSED(stream), long UNUSED(errcode), long UNUSED(serious))
{
    return 0;
}

void mm_fatal(char *string)
{
    mailSession *session = Ns_TlsGet(&mailTls);
    char *s;

    if (!session) return;
    s = ns_malloc(strlen(string) + 32);
    sprintf(s, "Fatal: %s", string);
    mm_log(string, ERROR);
    ns_free(s);
    longjmp(session->jmp, 1);
}

static void mm_parseline(ENVELOPE * UNUSED(env), char *hdr, char *data, char *UNUSED(host))
{
    mailSession *session = Ns_TlsGet(&mailTls);

    if (!session) return;
    Ns_SetPut(session->headers, hdr, data);
}

static void mm_getquota(MAILSTREAM * UNUSED(stream), char *UNUSED(qroot), QUOTALIST * qlist)
{
    mailSession *session = Ns_TlsGet(&mailTls);

    if (!session) return;
    for (; qlist; qlist = qlist->next) {
        Tcl_Obj *attr = Tcl_NewListObj(0, 0);
        Tcl_ListObjAppendElement(session->interp, attr, Tcl_NewStringObj(qlist->name, -1));
        Tcl_ListObjAppendElement(session->interp, attr, Tcl_NewIntObj((int) qlist->usage));
        Tcl_ListObjAppendElement(session->interp, attr, Tcl_NewIntObj((int) qlist->limit));
        Tcl_ListObjAppendElement(session->interp, session->list, attr);
    }
}

/* Modified UTF7 conversion functions from  Andrew Skalski <askalski@chek.com> */

/* tests `c' and returns true if it is a special character */
#define SPECIAL(c) ((c) <= 0x1f || (c) >= 0x7f)

/* validate a modified-base64 character */
#define B64CHAR(c) (isalnum(c) || (c) == '+' || (c) == ',')

/* map the low 64 bits of `n' to the modified-base64 characters */
#define B64(n)  ("ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                "abcdefghijklmnopqrstuvwxyz0123456789+,"[(n) & 0x3f])

/* map the modified-base64 character `c' to its 64 bit value */
#define UNB64(c)        ((c) == '+' ? 62 : (c) == ',' ? 63 : (c) >= 'a' ? \
                        (c) - 71 : (c) >= 'A' ? (c) - 65 : (c) + 4)

/* Decode a modified UTF-7 string */
static char *utf7_decode(char *in, int inlen, int *outlen)
{
    unsigned char *inp, *endp, *out, *outp;
    enum {
        ST_NORMAL,              /* printable text */
        ST_DECODE0,             /* encoded text rotation... */
        ST_DECODE1,
        ST_DECODE2,
        ST_DECODE3
    } state;

    /* validate and compute length of output string */
    *outlen = 0;
    state = ST_NORMAL;
    for (endp = (inp = (unsigned char*)in) + inlen; inp < endp; inp++) {
        if (state == ST_NORMAL) {
            /* process printable character */
            if (SPECIAL(*inp))
                return 0;
            else if (*inp != '&')
                (*outlen)++;
            else if (inp + 1 == endp)
                return 0;
            else if (inp[1] != '-')
                state = ST_DECODE0;
            else {
                (*outlen)++;
                inp++;
            }
        } else if (*inp == '-') {
            /* return to NORMAL mode */
            if (state == ST_DECODE1)
                return 0;
            state = ST_NORMAL;
        } else if (!B64CHAR(*inp)) {
            return 0;
        } else {
            switch (state) {
            case ST_DECODE3:
                (*outlen)++;
                state = ST_DECODE0;
                break;
            case ST_DECODE2:
            case ST_DECODE1:
                (*outlen)++;
            case ST_DECODE0:
                state++;
            case ST_NORMAL:
                break;
            }
        }
    }
    /* enforce end state */
    if (state != ST_NORMAL)
        return 0;
    /* allocate output buffer */
    if ((out = ns_malloc((unsigned) (*outlen) + 1)) == NULL)
        return 0;
    /* decode input string */
    outp = out;
    state = ST_NORMAL;
    for (endp = (inp = (unsigned char*)in) + inlen; inp < endp; inp++) {
        if (state == ST_NORMAL) {
            if (*inp == '&' && inp[1] != '-')
                state = ST_DECODE0;
            else if ((*outp++ = *inp) == '&')
                inp++;
            else if (*inp == '-')
                state = ST_NORMAL;
        } else {
            /* decode input character */
            switch (state) {
            case ST_DECODE0:
                *outp = UCHAR(UNB64(*inp) << 2);
                state = ST_DECODE1;
                break;
            case ST_DECODE1:
                outp[1] = UNB64(*inp);
                *outp = outp[1] >> 4;
                outp++;
                *outp <<= 4;
                state = ST_DECODE2;
                break;
            case ST_DECODE2:
                outp[1] = UNB64(*inp);
                *outp = outp[1] >> 2;
                outp++;
                *outp <<= 6;
                state = ST_DECODE3;
                break;
            case ST_DECODE3:
                *outp++ |= UNB64(*inp);
                state = ST_DECODE0;
            case ST_NORMAL:
                break;
            }
        }
    }
    *outp = 0;
    return (char*)out;
}

/* Encode a string in modified UTF-7 */
static char *utf7_encode(char *in, int inlen, int *outlen)
{
    unsigned char *inp, *endp, *out, *outp;
    enum {
        ST_NORMAL,              /* printable text */
        ST_ENCODE0,             /* encoded text rotation... */
        ST_ENCODE1,
        ST_ENCODE2
    } state;

    /* compute the length of the result string */
    (*outlen) = 0;
    state = ST_NORMAL;
    endp = (inp = (unsigned char*)in) + inlen;
    while (inp < endp) {
        if (state == ST_NORMAL) {
            if (SPECIAL(*inp))
                state = ST_ENCODE0, (*outlen)++;
            else if (*inp++ == '&')
                (*outlen)++;
            (*outlen)++;
        } else if (!SPECIAL(*inp)) {
            state = ST_NORMAL;
        } else {
            /* ST_ENCODE0 -> ST_ENCODE1     - two chars
             * ST_ENCODE1 -> ST_ENCODE2     - one char
             * ST_ENCODE2 -> ST_ENCODE0     - one char
             */
            if (state == ST_ENCODE2)
                state = ST_ENCODE0;
            else if (state++ == ST_ENCODE0)
                (*outlen)++;
            (*outlen)++;
            inp++;
        }
    }
    /* allocate output buffer */
    if ((out = ns_malloc((unsigned) (*outlen) + 1)) == NULL)
        return 0;
    /* encode input string */
    outp = out;
    state = ST_NORMAL;
    endp = (inp = (unsigned char*)in) + inlen;
    while (inp < endp || state != ST_NORMAL) {
        if (state == ST_NORMAL) {
            /* begin encoding */
            if (SPECIAL(*inp))
                *outp++ = '&', state = ST_ENCODE0;
            else if ((*outp++ = *inp++) == '&')
                *outp++ = '-';
        } else if (inp == endp || !SPECIAL(*inp)) {
            /* flush overflow and terminate region */
            if (state != ST_ENCODE0) {
                *outp = UCHAR(B64(*outp));
                outp++;
            }
            *outp++ = '-';
            state = ST_NORMAL;
        } else {
            /* encode input character */
            switch (state) {
            case ST_ENCODE0:
                *outp++ = UCHAR(B64(*inp >> 2));
                *outp = UCHAR(*inp++ << 4);
                state = ST_ENCODE1;
                break;
            case ST_ENCODE1:
                *outp = UCHAR(B64(*outp | *inp >> 4));
                outp++;
                *outp = UCHAR(*inp++ << 2);
                state = ST_ENCODE2;
                break;
            case ST_ENCODE2:
                *outp = UCHAR(B64(*outp | *inp >> 6));
                outp++;
                *outp++ = UCHAR(B64(*inp++));
                state = ST_ENCODE0;
            case ST_NORMAL:
                break;
            }
        }
    }
    *outp = 0;
    return (char*)out;
}

static char *strStripHtml(char *str, const char *tags[])
{
    int i;
    char *tag = 0, *ptr, *buf, *end, c;

    ptr = buf = str = ns_strcopy(str);

    while (*ptr) {
        switch (*ptr) {
        case '<':
            tag = ++ptr;
            if (!strncmp(tag, "!--", 3)) {
                if ((end = strstr(tag + 3, "-->"))) {
                    ptr = end + 2;
                    tag = 0;
                    break;
                }
                *ptr = 0;
                tag = 0;
                break;
            }
            break;
        case '>':
            if (tag) {
                while (*tag == ' ')
                    tag++;
                for (end = tag; end < ptr && *end != ' '; end++);
                c = *end, *end = 0;
                for (i = 0; tags[i]; i++)
                    if (!strcasecmp(tag, tags[i]))
                        break;
                *end = c;
                if (!tags[i]) {
                    *buf++ = '<';
                    while (tag <= ptr)
                        *buf++ = *tag++;
                }
                tag = 0;
            }
            ptr++;
            break;
        default:
            if (!tag)
                *buf++ = *ptr;
            ptr++;
            break;
        }
    }
    *buf = '\0';
    return str;
}

static char *strLower(char *str)
{
    int i;
    for (i = 0; str[i]; i++) {
        if (!(str[i] & 0x80) && isupper(str[i])) {
            str[i] = CHARCONV(lower, str[i]);
        }
    }
    return str;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
