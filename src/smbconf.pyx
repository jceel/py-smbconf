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


import enum
from libc.stdint cimport *
cimport defs


cdef extern bint lp_load_global(const char *path)


class SambaConfigErrorCode(enum.IntEnum):
    OK = defs.SBC_ERR_OK
    NOT_IMPLEMENTED = defs.SBC_ERR_NOT_IMPLEMENTED
    NOT_SUPPORTED = defs.SBC_ERR_NOT_SUPPORTED
    UNKNOWN_FAILURE = defs.SBC_ERR_UNKNOWN_FAILURE
    NOMEM = defs.SBC_ERR_NOMEM
    INVALID_PARAM = defs.SBC_ERR_INVALID_PARAM
    BADFILE = defs.SBC_ERR_BADFILE
    NO_SUCH_SERVICE = defs.SBC_ERR_NO_SUCH_SERVICE
    IO_FAILURE = defs.SBC_ERR_IO_FAILURE
    CAN_NOT_COMPLETE = defs.SBC_ERR_CAN_NOT_COMPLETE
    NO_MORE_ITEMS = defs.SBC_ERR_NO_MORE_ITEMS
    FILE_EXISTS = defs.SBC_ERR_FILE_EXISTS
    ACCESS_DENIED = defs.SBC_ERR_ACCESS_DENIED


class SambaConfigException(Exception):
    def __init__(self, err):
        super(SambaConfigException, self).__init__(SambaConfigErrorCode(err))


cdef class SambaConfig(object):
    cdef defs.TALLOC_CTX *mem_ctx
    cdef defs.smbconf_ctx *conf
    cdef defs.smbconf_service **services
    cdef defs.smbconf_service *global_conf
    cdef uint32_t num_services

    def __init__(self, source):
        cdef defs.sbcErr err

        lp_load_global("") # XXX: Should be /usr/local/etc/smb4.conf?
        self.mem_ctx = <defs.TALLOC_CTX*>defs.talloc_new(NULL)
        err = defs.smbconf_init(self.mem_ctx, &self.conf, source)
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

        self.refresh()

    def __getitem__(self, item):
        cdef defs.sbcErr err
        cdef char *result

        err = defs.smbconf_get_global_parameter(self.conf, self.mem_ctx, item, &result)
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

        return result

    def __setitem__(self, key, value):
        cdef defs.sbcErr err

        err = defs.smbconf_set_global_parameter(self.conf, key, value)
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

    property shares:
        def __get__(self):
            cdef SambaSharesDict ret

            ret = SambaSharesDict.__new__(SambaSharesDict)
            ret.root = self
            return ret

    def refresh(self):
        cdef uint32_t num_shares
        cdef char **share_names
        cdef SambaShare share
        cdef defs.sbcErr err

        err = defs.smbconf_get_config(self.conf, self.mem_ctx, &self.num_services, &self.services)
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

        if self.num_services > 0:
            self.global_conf = self.services[0]


cdef class SambaSharesDict(dict):
    cdef SambaConfig root

    def __getitem__(self, item):
        cdef SambaShare share

        for i in range(0, self.root.num_services):
            if self.root.services[i].name == item:
                share = SambaShare.__new__(SambaShare)
                share.root = self.root
                share.service = self.root.services[i]
                return share

        raise KeyError(item)

    def __setitem__(self, key, value):
        pass

    def __delitem__(self, key):
        pass

    def __iter__(self):
        return iter(self.keys())

    def keys(self):
        return [self.root.services[i].name for i in range(0, self.root.num_services)]

    def values(self):
        cdef SambaShare share

        ret = []
        for i in range(0, self.root.num_services):
            share = SambaShare.__new__(SambaShare)
            share.root = self.root
            share.service = self.root.services[i]
            ret.append(share)

        return ret

    def items(self):
        return zip(self.keys(), self.values())



cdef class SambaShare(dict):
    cdef SambaConfig root
    cdef defs.smbconf_service *service

    def __getitem__(self, item):
        cdef defs.sbcErr err
        cdef char *ret

        err = defs.smbconf_get_parameter(self.root.conf, self.root.mem_ctx, self.service.name, item, &ret)
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

        return ret

    def __setitem__(self, key, value):
        pass

    def __delitem__(self, key):
        pass

    def __contains__(self, item):
        return item in self.keys()

    def __iter__(self):
        return iter(self.keys())

    def keys(self):
        return [self.service.param_names[i] for i in range(0, self.service.num_params)]

    def values(self):
        return [self.service.param_values[i] for i in range(0, self.service.num_params)]

    def items(self):
        return zip(self.keys(), self.values())