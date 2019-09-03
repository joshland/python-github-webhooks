#!/usr/bin/python
from flup.server.fcgi import WSGIServer
from webhooks import application

# From:
# https://gist.github.com/surik00/2fef149e2f1ea716d891283ef857cc00
class ScriptNameStripper(object):
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        environ['SCRIPT_NAME'] = ''
        return self.app(environ, start_response)

if __name__ == '__main__':
    WSGIServer(ScriptNameStripper(application), bindAddress='/tmp/webhooks.sock').run()
