import os
from flask import Blueprint, jsonify, request, current_app
from functools import wraps
from collections import defaultdict
import telepot
import ujson as json
import requests
import textwrap
from telepot.delegate import per_chat_id, create_open
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.types import TypeDecorator, VARCHAR
from sqlalchemy.ext.mutable import Mutable
from ConfigParser import SafeConfigParser
from threading import Thread
from heapq import heappush, heappop
from logging import getLogger
import logging
import sys
import traceback

class JSONEncodedDict(TypeDecorator):
    "Represents an immutable structure as a json-encoded string."
    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value

class MutableDict(Mutable, dict):
    @classmethod
    def coerce(cls, key, value):
        "Convert plain dictionaries to MutableDict."

        if not isinstance(value, MutableDict):
            if isinstance(value, dict):
                return MutableDict(value)
            # this call will raise ValueError
            return Mutable.coerce(key, value)
        else:
            return value

    def __setitem__(self, key, value):
        "Detect dictionary set events and emit change events."
        dict.__setitem__(self, key, value)
        self.changed()

    def clear(self):
        for key in self.keys():
            del self[key]

    def __delitem__(self, key):
        "Detect dictionary del events and emit change events."
        dict.__delitem__(self, key)
        self.changed()

MutableDict.associate_with(JSONEncodedDict)

# logging part
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = getLogger(u'tgbots.wordpress_com_bot')

# config.conf
configparser = SafeConfigParser(os.environ)
configparser.read(
    os.path.join(
        os.environ.get(u'OPENSHIFT_DATA_DIR', u'.'),
        u'config.conf'))
config = dict(configparser.items(u'default'))

# sqlalchemy create engine and one global session.
# having a global session is bad, but it is recommended to have a single session.
# simple workaround is to have a scoped session using contextlib.contextmanager
# or have a db thread and send ops to that thread so that we will use only one session, for all threads.
engine = create_engine(
    u'postgresql://{username}:{password}@{postgresql_host}:{postgresql_port}/{dbname}'.format(
        username=config[u'psqldb_username'],
        password=config[u'psqldb_password'],
        postgresql_host=config[u'psqldb_host'],
        postgresql_port=config[u'psqldb_port'],
        dbname=config[u'psqldb_dbname']
    ), echo=True)
if not database_exists(engine.url):
    create_database(engine.url)

Session = sessionmaker(bind=engine)
session = Session()
Base = declarative_base()

# user model
class User(Base):
    __tablename__ = u'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(63), nullable=False, unique=True)
    access_token = Column(String(127), nullable=False)
    data = Column(JSONEncodedDict, nullable=False)

Base.metadata.create_all(engine)

# telepot Delegation Mechanism
class Conversation(telepot.helper.ChatHandler):
    def __init__(self, seed_tuple, timeout):
        super(Conversation, self).__init__(seed_tuple, timeout)
        self.callback = {
            u'/createpost': self.createpost,
            u'/authorize': self.authorize,
            u'/set_default_site': self.set_default_site,
            u'/set-default-site': self.set_default_site,
            u'/setdefaultsite': self.set_default_site,
            u'/set_title': self.set_title,
            u'/set-title': self.set_title,
            u'/settitle': self.set_title,
            u'/set_content': self.set_content,
            u'/set-content': self.set_content,
            u'/setcontent': self.set_content,
            u'/cancel': self.cancel,
            u'/review': self.review,
            u'/status': self.status,
            u'/sendpost': self.sendpost,
            u'/start': self.start
        }
        msg = seed_tuple[1]
        self.username = msg[u'from'][u'username']
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        if user_dbref is None:
            session.add(
                User(
                    username=self.username,
                    access_token='dummyToken',
                    data={}))
            session.commit()

    def start(self, msg, text):
        helpmsg = u"""
            help:
                to use this bot first authorize this. click on the link.
                {wp_oauth_link}
        """
        return self.sender.sendMessage(
            textwrap.dedent(helpmsg).format(wp_oauth_link=self.getOauth(self.username)))

    def cancel(self, msg, text):
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        if len(user_dbref.data) == 0:
            return self.sender.sendMessage(u'no operation to cancel.')
        curop = user_dbref.data[u'operation']
        user_dbref.data.clear()
        session.commit()
        return self.sender.sendMessage(u'%s cancelled' % curop)

    def createpost(self, msg, text):
        u"""
        usage:
            /createpost [site]
                *:---------
                /set_title
                title html here
                *:---------
                /set_content
                content html here
                *:---------
        ref:
            for complete documentation send /help
        """
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        if len(user_dbref.data) != 0:
            return self.sender.sendMessage(
                u'you are in the middle of an operation! please cancel that first with /cancel')
        user_dbref.data[u'operation'] = u'createpost'
        session.commit()

    def getOauth(self, username):
        return (
            u"https://public-api.wordpress.com"
            u"/oauth2"
            u"/authorize" \
                u"?client_id={client_id}"
                u"&redirect_uri={redirect_uri}"
                u"&response_type=code"
                u"&scope=global").format(
                    client_id=config[u'wpapi_client_id'],
                    redirect_uri=config[u'wpapi_redirect_uri'])

    def authorize(self, msg, text):
        u"""
        usage:
            /authorize [code]
        """
        helpmsg = u"""
            help:
                to authorize this app follow the below link
                {wp_oauth_link}
        """
        code = msg[u'text'].partition(u'\n')[0].partition(u' ')[2]
        if not code:
            return self.sender.sendMessage(
                textwrap.dedent(helpmsg).format(wp_oauth_link=self.getOauth(self.username)))
        resp = requests.post(
            u'https://public-api.wordpress.com/oauth2/token',
            data={
                u'client_id': config[u'wpapi_client_id'],
                u'redirect_uri': config[u'wpapi_redirect_uri'],
                u'client_secret': config[u'wpapi_client_secret'],
                u'code': code,
                u'grant_type': u'authorization_code',
            })
        if resp.status_code != 200:
            return self.sender.sendMessage('authorization failed! please enter the correct code')
        authinfo = resp.json()
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        user_dbref.access_token = authinfo[u'access_token']
        session.commit()
        return self.sender.sendMessage('authorization successfull!')

    def set_default_site(self, msg, text):
        u"""
        /set_default_site site
            stores your default_site for /createpost
        """
        # store default_site for this user in our postgresql database
        return

    def set_title(self, msg, text):
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        if user_dbref.data.get(u'operation') != u'createpost':
            return self.sender.sendMessage(
                'error: this command belongs to createpost. first go to /createpost')
        user_dbref.data[u'title'] = text
        session.commit()

    def set_content(self, msg, text):
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        if user_dbref.data.get(u'operation') != u'createpost':
            return self.sender.sendMessage(
                'error: this command belongs to createpost. first go to /createpost')
        user_dbref.data[u'content'] = text
        session.commit()

    def review(self, msg, text):
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        if not len(user_dbref.data):
            return self.sender.sendMessage(u'no operation to review.')
        return self.sender.sendMessage(
            json.dumps(dict(user_dbref.data)))

    def status(self, msg, text):
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        if not len(user_dbref.data):
            return self.sender.sendMessage(u'status: idle')
        return self.sender.sendMessage(u'status: %s operation' % user_dbref.data[u'operation'])

    def sendpost(self, msg, text):
        help_msg = u'''
        /sendpost {{site_address}}
            site_address should be one of your blog address,
            if you are not a owner of the blog you will
            get invalid token error.
        '''
        user_dbref = session.query(User).filter(User.username == self.username).one_or_none()
        if user_dbref.data.get(u'operation') != u'createpost':
            return self.sender.sendMessage(
                'error: this command belongs to createpost. first go to /createpost')
        _, _, site = msg[u'text'].partition(u'\n')[0].partition(u' ')
        if not site:
            return self.sender.sendMessage('invalid params'), self.sender.sendMessage(textwrap.dedent(help_msg))
        resp = requests.post(
            'https://public-api.wordpress.com/rest/v1.1/sites/{site}/posts/new/'.format(site=site),
            data={
                u'title': user_dbref.data.get(u'title', u''),
                u'content': user_dbref.data.get(u'content', u''),
            },
            headers={
                u'authorization': u'Bearer %s' % user_dbref.access_token
            }
        )
        if resp.status_code == 400:
            return self.sender.sendMessage(u'invalid token. try authorizing the app again.')
        if resp.status_code == 403:
            return self.sender.sendMessage(u'403, forbidden. you don\'t have permission to create a post on %s' % site)
        if resp.status_code != 200:
            return self.sender.sendMessage('unknown error. error code received is %s' % resp.status_code)
        user_dbref.data.clear()
        session.commit()
        return self.sender.sendMessage(resp.json()[u'URL'])

    def on_message(self, msg):
        try:
            # check if the msg is text. and bot only accepts commands.
            if u'text' not in msg or msg[u'text'][0] != u'/':
                return self.sender.sendMessage(u'not a command!')
            cmdline, _, text = msg[u'text'].partition(u'\n')
            cmd = cmdline.partition(u' ')[0]
            if cmd not in self.callback:
                return self.sender.sendMessage(u'unrecognized command!')
            return self.callback[cmd](msg, text)
        except Exception, e:
            logger.error(str(e))
            ex_type, ex, tb = sys.exc_info()
            traceback.print_tb(tb)
            return self.sender.sendMessage(u'500: server error!')

wpbot = telepot.DelegatorBot(
    config[u'wordpress_com_bot_token'],
    [(per_chat_id(), create_open(Conversation, timeout=600))])

# flask blueprint app, much like that you get from flask.Flask()
wpbotapp = Blueprint(u'wordpress_com_bot', __name__)

# keeping a recent_updates heap to ignore same updates from telegram.
recent_updates = []

@wpbotapp.route(u'/' + config[u'wordpress_com_bot_token'], methods=[u'POST'])
def webhook():
    update = request.get_json()
    if update[u'update_id'] in recent_updates:
        return u'', 200
    heappush(recent_updates, update[u'update_id'])
    if len(recent_updates) >= 100:
        heappop(recent_updates)
    try:
        wpbot.handle(update[u'message'])
    except Exception, e:
        print e
        return u'', 500
    return u'', 200

@wpbotapp.route(u'/')
def home():
    return jsonify({u'Display Available Commands':u'none'})
