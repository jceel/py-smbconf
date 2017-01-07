#+
# Copyright 2015 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

from libc.stdint cimport *
from posix.unistd cimport uid_t, gid_t, pid_t
from posix.time cimport time_t


ctypedef char[256] fstring


cdef extern from "stdbool.h":
    ctypedef bint bool


cdef extern from "talloc.h":
    ctypedef struct TALLOC_CTX:
        pass

    void *talloc_new(const void *ctx)
    char *talloc_strdup(const void *t, const char *p)
    void *talloc_realloc_fn(const void *ctx, void *ptr, size_t size)


cdef extern from "tevent.h":
    cdef struct tevent_context:
        pass

    tevent_context *tevent_context_init(TALLOC_CTX *mem_ctx)


cdef extern from "samba4/smbconf.h" nogil:
    ctypedef enum sbcErr:
        SBC_ERR_OK
        SBC_ERR_NOT_IMPLEMENTED
        SBC_ERR_NOT_SUPPORTED
        SBC_ERR_UNKNOWN_FAILURE
        SBC_ERR_NOMEM
        SBC_ERR_INVALID_PARAM
        SBC_ERR_BADFILE
        SBC_ERR_NO_SUCH_SERVICE
        SBC_ERR_IO_FAILURE
        SBC_ERR_CAN_NOT_COMPLETE
        SBC_ERR_NO_MORE_ITEMS
        SBC_ERR_FILE_EXISTS
        SBC_ERR_ACCESS_DENIED

    cdef struct smbconf_csn:
        pass

    cdef struct smbconf_ctx:
        pass

    cdef struct smbconf_service:
        char *name
        uint32_t num_params
        char **param_names
        char **param_values

    sbcErr smbconf_init(TALLOC_CTX *mem_ctx, smbconf_ctx **conf_ctx, const char *source)
    bool smbconf_backend_requires_messaging(smbconf_ctx *ctx)
    bool smbconf_is_writeable(smbconf_ctx *ctx)
    void smbconf_shutdown(smbconf_ctx *ctx)
    bool smbconf_changed(smbconf_ctx *ctx, smbconf_csn *csn, const char *service, const char *param)
    sbcErr smbconf_drop(smbconf_ctx *ctx)
    sbcErr smbconf_get_config(smbconf_ctx *ctx, TALLOC_CTX *mem_ctx, uint32_t *num_shares, smbconf_service ***services)
    sbcErr smbconf_get_share_names(smbconf_ctx *ctx, TALLOC_CTX *mem_ctx, uint32_t *num_shares, char ***share_names)
    bool smbconf_share_exists(smbconf_ctx *ctx, const char *servicename)
    sbcErr smbconf_create_share(smbconf_ctx *ctx, const char *servicename)
    sbcErr smbconf_create_set_share(smbconf_ctx *ctx, smbconf_service *service)
    sbcErr smbconf_get_share(smbconf_ctx *ctx, TALLOC_CTX *mem_ctx, const char *servicename, smbconf_service **service)
    sbcErr smbconf_delete_share(smbconf_ctx *ctx, const char *servicename)
    sbcErr smbconf_set_parameter(smbconf_ctx *ctx, const char *service, const char *param, const char *valstr)
    sbcErr smbconf_set_global_parameter(smbconf_ctx *ctx, const char *param, const char *val)
    sbcErr smbconf_get_parameter(smbconf_ctx *ctx, TALLOC_CTX *mem_ctx, const char *service, const char *param, char **valstr)
    sbcErr smbconf_get_global_parameter(smbconf_ctx *ctx, TALLOC_CTX *mem_ctx, const char *param, char **valstr)
    sbcErr smbconf_delete_parameter(smbconf_ctx *ctx, const char *service, const char *param)
    sbcErr smbconf_delete_global_parameter(smbconf_ctx *ctx, const char *param)
    sbcErr smbconf_get_includes(smbconf_ctx *ctx, TALLOC_CTX *mem_ctx, const char *service, uint32_t *num_includes, char ***includes)
    sbcErr smbconf_get_global_includes(smbconf_ctx *ctx, TALLOC_CTX *mem_ctx, uint32_t *num_includes, char ***includes)
    sbcErr smbconf_set_includes(smbconf_ctx *ctx, const char *service, uint32_t num_includes, const char **includes)
    sbcErr smbconf_set_global_includes(smbconf_ctx *ctx, uint32_t num_includes, const char **includes)
    sbcErr smbconf_delete_includes(smbconf_ctx *ctx, const char *service)
    sbcErr smbconf_delete_global_includes(smbconf_ctx *ctx)
    sbcErr smbconf_transaction_start(smbconf_ctx *ctx)
    sbcErr smbconf_transaction_commit(smbconf_ctx *ctx)
    sbcErr smbconf_transaction_cancel(smbconf_ctx *ctx)


cdef extern from "core/werror.h":
    pass


cdef extern from "util/time.h":
    pass


cdef extern from "util/data_blob.h":
    pass


cdef extern from "gen_ndr/server_id.h":
    cdef struct server_id:
        pid_t pid
        uint64_t unique_id


cdef struct sessionid:
    uid_t uid
    gid_t gid
    fstring username
    fstring hostname
    fstring netbios_name
    fstring remote_machine
    fstring id_str
    uint32_t id_num
    server_id pid
    fstring ip_addr_str
    time_t connect_start
    fstring protocol_ver


cdef struct connections_key:
    server_id pid
    int cnum
    fstring name


cdef struct connections_data:
    server_id pid
    int cnum
    uid_t uid
    gid_t gid
    fstring servicename
    fstring addr
    fstring machine
    time_t start


cdef enum:
    MSG_DEBUG = 0x0001
    MSG_PING = 0x0002
    MSG_PONG = 0x0003
    MSG_PROFILE = 0x0004
    MSG_REQ_DEBUGLEVEL = 0x0005
    MSG_DEBUGLEVEL = 0x0006
    MSG_REQ_PROFILELEVEL = 0x0007
    MSG_PROFILELEVEL = 0x0008
    MSG_REQ_POOL_USAGE = 0x0009
    MSG_POOL_USAGE = 0x000A
    MSG_REQ_DMALLOC_MARK = 0x000B
    MSG_REQ_DMALLOC_LOG_CHANGED = 0x000C
    MSG_SHUTDOWN = 0x000D
    ID_CACHE_DELETE = 0x000F
    ID_CACHE_KILL = 0x0010
    MSG_SMB_CONF_UPDATED = 0x0021
    MSG_PREFORK_CHILD_EVENT = 0x0031
    MSG_PREFORK_PARENT_EVENT = 0x0032
    MSG_FORCE_ELECTION = 0x0101
    MSG_WINS_NEW_ENTRY = 0x0102
    MSG_SEND_PACKET = 0x0103
    MSG_PRINTER_NOTIFY2 = 0x0202
    MSG_PRINTER_DRVUPGRADE = 0x0203
    MSG_PRINTERDATA_INIT_RESET = 0x0204
    MSG_PRINTER_UPDATE = 0x0205
    MSG_PRINTER_MOD = 0x0206
    MSG_PRINTER_PCAP = 0x0207
    MSG_SMB_FORCE_TDIS = 0x0302
    MSG_SMB_UNLOCK = 0x0305
    MSG_SMB_BREAK_REQUEST = 0x0306
    MSG_SMB_KERNEL_BREAK = 0x030A
    MSG_SMB_FILE_RENAME = 0x030B
    MSG_SMB_INJECT_FAULT = 0x030C
    MSG_SMB_BLOCKING_LOCK_CANCEL = 0x030D
    MSG_SMB_NOTIFY = 0x030E
    MSG_SMB_STAT_CACHE_DELETE = 0x030F
    MSG_PVFS_NOTIFY = 0x0310
    MSG_SMB_BRL_VALIDATE = 0x0311
    MSG_SMB_CLOSE_FILE = 0x0313
    MSG_SMB_NOTIFY_CLEANUP = 0x0314
    MSG_SMB_SCAVENGER = 0x0315
    MSG_SMB_KILL_CLIENT_IP = 0x0316
    MSG_SMB_TELL_NUM_CHILDREN = 0x0317
    MSG_SMB_NUM_CHILDREN = 0x0318
    MSG_SMB_NOTIFY_CANCEL_DELETED = 0x0319
    MSG_WINBIND_FINISHED = 0x0401
    MSG_WINBIND_FORGET_STATE = 0x0402
    MSG_WINBIND_ONLINE = 0x0403
    MSG_WINBIND_OFFLINE = 0x0404
    MSG_WINBIND_ONLINESTATUS = 0x0405
    MSG_WINBIND_TRY_TO_GO_ONLINE = 0x0406
    MSG_WINBIND_FAILED_TO_GO_ONLINE = 0x0407
    MSG_WINBIND_VALIDATE_CACHE = 0x0408
    MSG_WINBIND_DUMP_DOMAIN_LIST = 0x0409
    MSG_WINBIND_IP_DROPPED = 0x040A
    MSG_WINBIND_DOMAIN_ONLINE = 0x040B
    MSG_WINBIND_DOMAIN_OFFLINE = 0x040C
    MSG_WINBIND_NEW_TRUSTED_DOMAIN = 0x040D
    MSG_DUMP_EVENT_LIST = 0x0500
    MSG_SMBXSRV_SESSION_CLOSE = 0x0600
    MSG_BRL_RETRY = 0x0700
    MSG_PVFS_RETRY_OPEN = 0x0701
    MSG_IRPC = 0x0702
    MSG_NTVFS_OPLOCK_BREAK = 0x0703
    MSG_DREPL_ALLOCATE_RID = 0x0704
    MSG_DBWRAP_MODIFIED = 4003
    MSG_TMP_BASE = 0xF000


cdef struct messaging_context:
    int dummy


cdef struct server_id:
    int dummy


cdef extern bool message_send_all(messaging_context *msg_ctx, int msg_type, const void *buf, size_t len, int *n_sent) nogil
cdef extern int messaging_send_buf(messaging_context *msg_ctx, server_id server, uint32_t msg_type, const uint8_t *buf, size_t len) nogil
cdef extern messaging_context *messaging_init(TALLOC_CTX *mem_ctx, tevent_context *ev)
cdef extern int messaging_cleanup(messaging_context *msg_ctx, pid_t pid)
cdef extern pid_t procid_to_pid(const server_id *proc)
cdef extern server_id pid_to_procid(pid_t pid);


cdef extern int sessionid_traverse_read(
    int (*fn)(const char *key, sessionid *session, void *private_data),
    void *private_data
)
cdef extern int connections_forall_read(
    int (*fn)(const connections_key *key, const connections_data *data, void *private_data),
    void *private_data
)
