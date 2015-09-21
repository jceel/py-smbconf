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


cdef extern from "stdbool.h":
    ctypedef bint bool


cdef extern from "talloc.h":
    ctypedef struct TALLOC_CTX:
        pass

    void *talloc_new(const void *ctx)


cdef extern from "samba4/smbconf.h":
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
