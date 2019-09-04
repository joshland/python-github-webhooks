#!/usr/bin/python3
from flup.server.fcgi import WSGIServer
from webhooks import application

if __name__ == '__main__':
    WSGIServer(application, bindAddress='/tmp/webhooks.sock-0').run()
