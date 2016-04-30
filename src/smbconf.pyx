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

import os
import enum
import cython
from libc.stdint cimport *
from libc.string cimport memcpy, strlen
cimport defs


cdef extern const char *lp_pid_directory()
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
        self.code = SambaConfigErrorCode(err)


cdef class SambaConfig(object):
    cdef defs.TALLOC_CTX *mem_ctx
    cdef defs.smbconf_ctx *conf
    cdef defs.smbconf_service **services
    cdef defs.smbconf_service *global_conf
    cdef uint32_t num_services

    def __init__(self, source):
        cdef defs.sbcErr err

        self.mem_ctx = <defs.TALLOC_CTX*>defs.talloc_new(NULL)
        err = defs.smbconf_init(self.mem_ctx, &self.conf, source.encode('utf8'))
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

        self.refresh()

    def __getitem__(self, item):
        cdef defs.sbcErr err
        cdef char *result

        err = defs.smbconf_get_global_parameter(self.conf, self.mem_ctx, item.encode('utf8'), &result)
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

        return result

    def __setitem__(self, key, value):
        cdef defs.sbcErr err

        err = defs.smbconf_set_global_parameter(self.conf, key.encode('utf8'), value.encode('utf8'))
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

    def __delitem__(self, key):
        cdef defs.sbcErr err

        err = defs.smbconf_delete_global_parameter(self.conf, key.encode('utf8'))
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

    def __contains__(self, item):
        try:
            _ = self[item]
        except SambaConfigException, err:
            if err.code == SambaConfigErrorCode.INVALID_PARAM:
                return False

            raise

        return True

    def update(self, otherdict):
        for k, v in otherdict.values():
            self[k] = v

    property shares:
        def __get__(self):
            cdef SambaSharesDict ret

            ret = SambaSharesDict.__new__(SambaSharesDict)
            ret.root = self
            return ret

    cdef defs.smbconf_service* service_by_name(self, name):
        for i in range(0, self.num_services):
            if self.services[i].name.decode('utf8') == name:
                return self.services[i]

        return NULL

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

    def __repr__(self):
        return "{" + ', '.join(["'{0}': {1}".format(k, str(v)) for k, v in self.items()]) + "}"

    def __str__(self):
        return repr(self)

    def __getitem__(self, item):
        cdef SambaShare share

        for i in range(0, self.root.num_services):
            if self.root.services[i].name.decode('ascii') == item:
                share = SambaShare.__new__(SambaShare)
                share.root = self.root
                share.service = self.root.services[i]
                share.refresh()
                return share

        raise KeyError(item)

    def __setitem__(self, key, SambaShare value):
        cdef defs.sbcErr err

        if not isinstance(value, SambaShare):
            raise ValueError('Can only assign SambaShare instances')

        err = defs.smbconf_create_share(self.root.conf, defs.talloc_strdup(self.root.mem_ctx, key.encode('utf8')))
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

        self.root.refresh()
        value.root = self.root
        value.service = self.root.service_by_name(key)
        value.save()

    def __delitem__(self, key):
        cdef defs.sbcErr err

        err = defs.smbconf_delete_share(self.root.conf, key.encode('utf8'))
        if err != defs.SBC_ERR_OK:
            raise SambaConfigException(err)

        self.root.refresh()

    def __iter__(self):
        return iter(self.keys())

    def __contains__(self, item):
        return item in self.keys()

    def keys(self):
        return filter(
            lambda n: n != 'global',
            [self.root.services[i].name.decode('utf8') for i in range(0, self.root.num_services)]
        )

    def values(self):
        cdef SambaShare share

        ret = []
        for i in range(0, self.root.num_services):
            if self.root.services[i].name.decode('utf8') == 'global':
                continue

            share = SambaShare.__new__(SambaShare)
            share.root = self.root
            share.service = self.root.services[i]
            share.refresh()
            ret.append(share)

        return ret

    def items(self):
        return zip(self.keys(), self.values())

    def clear(self):
        for i in self.keys():
            del self[i]


cdef class SambaShare(dict):
    cdef public SambaConfig root
    cdef defs.smbconf_service *service

    def __repr__(self):
        return "<smbconf.SambaShare '{0}'>".format(self.name)

    def __str__(self):
        return repr(self)

    def refresh(self):
        self.clear()
        for i in range(0, self.service.num_params):
            self[self.service.param_names[i]] = self.service.param_values[i]

    def save(self):
        cdef defs.sbcErr err

        if not self.root:
            raise ValueError('Object is not attached to SambaConfig instance')

        for k, v in self.items():
            err = defs.smbconf_set_parameter(self.root.conf, self.name.encode('utf8'), k.encode('utf8'), v.encode('utf8'))
            if err != defs.SBC_ERR_OK:
                raise SambaConfigException(err)

        for i in range(0, self.service.num_params):
            if self.service.param_names[i].decode('utf8') not in self:
                err = defs.smbconf_delete_parameter(self.root.conf, self.name.encode('utf8'), self.service.param_names[i])

    property name:
        def __get__(self):
            if self.service == NULL:
                return '<unnamed>'

            return self.service.name.decode('utf8')


cdef class SambaSession(object):
    cdef defs.sessionid session

    def __getstate__(self):
        return {
            'uid': self.uid,
            'username': self.username,
            'hostname': self.hostname,
            'netbios_name': self.netbios_name,
            'remote_machine': self.remote_machine,
            'id': self.id,
            'ip_address': self.ip_address,
            'protocol_version': self.protocol_version
        }

    property uid:
        def __get__(self):
            return self.session.uid

    property username:
        def __get__(self):
            return self.session.username.decode('utf-8')

    property hostname:
        def __get__(self):
            return self.session.hostname.decode('utf-8')

    property netbios_name:
        def __get__(self):
            return self.session.netbios_name.decode('utf-8')

    property remote_machine:
        def __get__(self):
            return self.session.remote_machine.decode('utf-8')

    property id:
        def __get__(self):
            return self.session.id_str.decode('utf-8')

    property ip_address:
        def __get__(self):
            return self.session.ip_addr_str.decode('utf-8')

    property protocol_version:
        def __get__(self):
            return self.session.protocol_ver.decode('utf-8')


cdef class SambaConnection(object):
    cdef defs.connections_key key
    cdef defs.connections_data data

    def __getstate__(self):
        return {
            'uid': self.uid,
            'gid': self.gid,
            'service_name': self.service_name,
            'address': self.address,
            'machine': self.machine,
            'start': self.start
        }

    property uid:
        def __get__(self):
            return self.data.uid

    property gid:
        def __get__(self):
            return self.data.gid

    property service_name:
        def __get__(self):
            return self.data.servicename.decode('utf-8')

    property address:
        def __get__(self):
            return self.data.addr.decode('utf-8')

    property machine:
        def __get__(self):
            return self.data.machine.decode('utf-8')

    property start:
        def __get__(self):
            return self.data.start


cdef class SambaMessagingContext(object):
    cdef defs.tevent_context *evt_ctx
    cdef defs.messaging_context *msg_ctx

    def __init__(self):
        self.evt_ctx = defs.tevent_context_init(NULL)
        self.msg_ctx = defs.messaging_init(NULL, self.evt_ctx)

    def __send_msg(self, msg_type, value=None):
        cdef defs.server_id procid
        cdef char *c_value = NULL
        cdef int c_msg_type = msg_type
        cdef int len = 0

        procid = defs.pid_to_procid(self.smbd_pid)

        if value is not None:
            value = value.encode('utf-8')
            c_value = <char *>value
            len = strlen(c_value) + 1

        with nogil:
            defs.messaging_send_buf(
                self.msg_ctx,
                procid,
                c_msg_type,
                <const uint8_t *>c_value,
                len
            )

    def kill_share_connections(self, share):
        self.__send_msg(defs.MSG_SMB_FORCE_TDIS, share)

    def kill_user_connection(self, ip):
        self.__send_msg(defs.MSG_SMB_KILL_CLIENT_IP, ip)

    def reload_config(self):
        self.__send_msg(defs.MSG_SMB_CONF_UPDATED)

    property pidfile_directory:
        def __get__(self):
            return lp_pid_directory().decode('utf-8')

    property smbd_pid:
        def __get__(self):
            with open(os.path.join(self.pidfile_directory, 'smbd.pid')) as f:
                return int(f.read().strip())

    property nmbd_pid:
        def __get__(self):
            with open(os.path.join(self.pidfile_directory, 'nmbd.pid')) as f:
                return int(f.read().strip())

    property winbindd_pid:
        def __get__(self):
            with open(os.path.join(self.pidfile_directory, 'winbindd.pid')) as f:
                return int(f.read().strip())


cdef int session_traverse_callback(const char *key, defs.sessionid *session, void *priv):
    cdef SambaSession ses

    obj = <object>priv
    ses = SambaSession.__new__(SambaSession)
    memcpy(&ses.session, session, cython.sizeof(defs.sessionid))
    obj.append(ses)
    return 0


cdef int connection_forall_callback(const defs.connections_key *key, const defs.connections_data *data, void *priv):
    cdef SambaConnection conn

    obj = <object>priv
    conn = SambaConnection.__new__(SambaConnection)
    memcpy(&conn.key, key, cython.sizeof(defs.connections_key))
    memcpy(&conn.data, data, cython.sizeof(defs.connections_data))
    obj.append(conn)
    return 0


def get_active_sessions():
    ret = []
    defs.sessionid_traverse_read(session_traverse_callback, <void*>ret)
    return ret


def get_active_users():
    ret = []
    defs.connections_forall_read(connection_forall_callback, <void*>ret)
    return ret


lp_load_global("") # XXX: Should be /usr/local/etc/smb4.conf?
