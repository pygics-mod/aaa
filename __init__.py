# -*- coding: utf-8 -*-
'''
Created on 2017. 8. 10.
@author: HyechurnJang
'''

import re
import json
import uuid
import time
import base64
import pygics
from settings import *
from bucket import *

if BACKEND_TYPE.lower() == 'memory':
    _aaa_bucket = MemoryBucket()
elif BACKEND_TYPE.lower() == 'file':
    _aaa_bucket = FileBucket()
elif BACKEND_TYPE.lower() == 'mysql':
    _aaa_bucket = MysqlBucket(BACKEND_MYSQL_HOST, BACKEND_MYSQL_USER, BACKEND_MYSQL_PASS)
else:
    raise Exception('unknown AAA backend type')

@Bucket.register(_aaa_bucket)
class User(Model):
    
    group_id = Column(Integer)
    username = Column(String(32))
    password = Column(String(32))
    
    def __init__(self, group_id, username, password):
        self.username = username
        self.password = password

@Bucket.register(_aaa_bucket)
class Group(Model):
    
    groupname = Column(String(32))
    
    def __init__(self, groupname):
        self.groupname = groupname

if not Group.one(Group.groupname=='admin'):
    _admin_group = Group('admin').create()

if not User.one(User.username==SUPER_USERNAME):
    User(_admin_group.id, SUPER_USERNAME, SUPER_PASSWORD).create()

_user_tokens = {}
_live_tokens = {}

def __getExpireTime__(): return int(time.time()) + TOKEN_EXPIRE
def __createNewToken__(): return str(uuid.uuid4()).replace('-', '')

def __inspectAuth__(req):
    if 'AUTHORIZATION' in req.headers:
        auth_type, auth_data = req.headers['AUTHORIZATION'].split(' ')
        if auth_type.lower() == 'basic':
            username, password = base64.b64decode(auth_data).split(':')
            user = User.one(User.username==username, User.password==password)
            if user:
                if username in _user_tokens:
                    token = _user_tokens[username]
                    _live_tokens[token]['expire'] = __getExpireTime__()
                    req.setCookie('AAA-TOKEN', _user_tokens[username])
                else:
                    token = __createNewToken__()
                    _user_tokens[username] = token
                    _live_tokens[token] = {'expire' : __getExpireTime__(), 'username' : username}
                    req.setCookie('AAA-TOKEN', token)
                return True
    return False

def __inspectToken__(req, user, group):
    if 'AAA-TOKEN' in req.cookies:
        token = req.cookies['AAA-TOKEN']
        if token in _live_tokens:
            _live_tokens[token]['expire'] = __getExpireTime__()
            return True
        else: return __inspectAuth__(req)
    else: return __inspectAuth__(req)

class __Terminator__(pygics.Task):
    
    def __init__(self):
        pygics.Task.__init__(self, tick=TOKEN_MONITOR)
        self.start()
    
    def run(self):
        curr = int(time.time())
        delete_token = []
        for token, value in _live_tokens.items():
            if value['expire'] < curr:
                _user_tokens.pop(value['username'])
                delete_token.append(token)
        for token in delete_token:
            _live_tokens.pop(token)

_terminator = __Terminator__()

def api_plugin(req, res, user, group, login_url=None):
    if not __inspectToken__(req, user, group):
        if login_url: raise pygics.Response.Redirect(login_url)
        else: raise pygics.Response.Unauthorized()
