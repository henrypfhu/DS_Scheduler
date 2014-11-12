#!/usr/bin/env python2

import getopt
import sys, os, pwd
import socket, ssl
import subprocess
import threading
import pyinotify
import datetime as dt
import sched_slaveconfig as conf
from OpenSSL import crypto, SSL
#from time import gmtime, mktime

if sys.version_info[0] >= 3:
   import pickle
   import socketserver
else:
   import cPickle
   import SocketServer

os.umask(0o077)

import sched_slaveconfig as conf

#Globals
event_queue = {}
lock = threading.Lock()
process_list = {} # list of current processes. useful for cleanup. 
C_F = os.path.join(conf.ssl_dir, conf.agent_certfile)
K_F = os.path.join(conf.ssl_dir, conf.CA_cert)

def usage():

   ''' Help and usage output. '''
   print('''Usage: sched_slave.py [OPTIONS]

Options:
 -d, --daemon          Detach from the shell and run as a daemon.
 -h, --help            Print this message.
''')

def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
   '''This forks the current process into a daemon. The stdin, stdout, and
   stderr arguments are file names that will be opened and be used to replace
   the standard file descriptors in sys.stdin, sys.stdout, and sys.stderr.
   These arguments are optional and default to /dev/null. Note that stderr is
   opened unbuffered, so if it shares a file with stdout then interleaved
   output may not appear in the order that you expect. '''

   # Do first fork.
   try: 
      pid = os.fork() 
      if pid > 0:
         sys.exit(0)   # Exit first parent.
   except OSError as e: 
      sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
      sys.exit(1)

   # Decouple from parent environment.
   os.chdir("/") 
   os.umask(0) 
   os.setsid() 

   # Do second fork.
   try: 
      pid = os.fork() 
      if pid > 0:
         sys.exit(0)   # Exit second parent.
   except OSError as e: 
      sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
      sys.exit(1)

   # Now I am a daemon!
    
   # Redirect standard file descriptors.
   si = open(stdin, 'r')
   so = open(stdout, 'a+')
   se = open(stderr, 'a+', 0)
   os.dup2(si.fileno(), sys.stdin.fileno())
   os.dup2(so.fileno(), sys.stdout.fileno())
   os.dup2(se.fileno(), sys.stderr.fileno())

def create_self_signed_cert():
   global C_F
   global K_F
   # create a key pair
   k = crypto.PKey()
   k.generate_key(crypto.TYPE_RSA, 1024)

   # create a self-signed cert
   cert = crypto.X509()
   cert.get_subject().C = 'US'
   cert.get_subject().ST = 'NY'
   cert.get_subject().L = 'Somwhere'
   cert.get_subject().O = 'DS_Scheduler'
   cert.get_subject().OU = 'DS_Scheduler'
   cert.get_subject().CN = 'agent'
   cert.set_serial_number(1000)
   cert.gmtime_adj_notBefore(0)
   cert.gmtime_adj_notAfter(315360000)
   cert.set_issuer(cert.get_subject())
   cert.set_pubkey(k)
   cert.sign(k, 'sha1')
   open(C_F, 'wt').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
   open(K_F, 'wt').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

def demote(user_uid):
   def result():
      os.setuid(user_uid)
   return result

def Log(msg):
   now = dt.datetime.now()
   print("%s :: %s" %(now, msg))

def add_queue(event, target):
   ''' To prevent duplicate events, keep a queue to keep track '''
   if target in event_queue.keys():
      return False
   else:
      lock.acquire()
      event_queue[target] = event
      lock.release()
      return True

def send_event(event, path, filename=""):
   global C_F
   global K_F
   hostname = socket.gethostname()
   Log("Sending Event %s for %s" % (event, filename))
   client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   ssl_socket = ssl.wrap_socket(client_socket, ca_certs=C_F, cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLSv1)
   ssl_socket.connect((conf.master_host, event_port))
   event_data = cPickle.dumps([event, hostname, path, filename])
   ssl_socket.send(event_data)
   ssl_socket.close()

class ModHandler(pyinotify.ProcessEvent):
    # evt has useful properties, including pathname
    def process_IN_CLOSE_WRITE(self, evt):
       send_event('ON_FILECHANGE', evt.path, filename=evt.pathname)
    def process_IN_CREATE(self, evt):
       send_event('ON_NEWFILE', evt.path, filename=evt.pathname)

class EventThread(threading.Thread):
   def run(self):
      self.exit_condition = False
      self.event = self._Thread__kwargs
      event = self.event[0]
      filename = self.event[1]
      handler = ModHandler()
      wm = pyinotify.WatchManager()
      notifier = pyinotify.Notifier(wm, handler)
      if event == "ON_NEWFILE":
         wdd = wm.add_watch(filename, pyinotify.IN_CREATE)
         Log("ON_NEWFILE Event listener running")
      elif event == "ON_FILECHANGE":
         wdd = wm.add_watch(filename, pyinotify.IN_CLOSE_WRITE)
         Log("ON_FILECHANGE Event listener running")
      else:
         return
      notifier.loop()

class SecureTCPServer(SocketServer.TCPServer):
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 certfile,
                 keyfile,
                 ssl_version=ssl.PROTOCOL_TLSv1,
                 bind_and_activate=True):
        
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile = self.certfile,
                                 keyfile = self.keyfile,
                                 ssl_version = self.ssl_version)
        return connstream, fromaddr

class Secure_ThreadingTCPServer(SocketServer.ThreadingMixIn, SecureTCPServer): pass

class RequestHandler(SocketServer.BaseRequestHandler ):
   def setup(self):
      #print self.client_address, 'connected!'
      pass

   def send_data(self, data):
      self.request.send(cPickle.dumps(data))

   def handle(self):
      rawdata = self.request.recv(4096)
#      try:
      cmd = cPickle.loads(rawdata)
      #print cmd
      if cmd[0].startswith('ON_'):
         Log("Received %s event for file %s" % (cmd[0], cmd[1]))
         if add_queue(cmd[1], cmd[0]):
            event_thread = EventThread(kwargs=cmd)
            event_thread.start()
         else:
            Log("Target event exists:%s %s" %(cmd[1], cmd[0]))
      elif cmd[0] == 'KILL':
         Log("Received KILL event for PID %s" % (cmd[1]) )
      else:
         user_uid = pwd.getpwnam(cmd[1])[2]
         Log("Received %s as user %s(%s)" % (cmd[0], cmd[1], user_uid))
         proc = subprocess.Popen( cmd[0], preexec_fn=demote(user_uid), stdout=subprocess.PIPE, shell=True)
         # Send the process PID up to the master
         pid = proc.pid
         #process_list['%s' % (pid)] = 0
         sendpid = [proc.pid, ]
         self.send_data(sendpid)
         # Now send the return code and the output up to the master. 
         output = proc.communicate()[0]
         return_code = proc.returncode
         #process_list.pop(pid)
         response = [return_code, output]
         self.send_data(response)
#      except UnpicklingError:
#         Log("Host key does not match. Permission denied.")

def main():
   global C_F
   global K_F
  
   if not os.path.exists(conf.ssl_dir):
      os.mkdir(conf.ssl_dir, 0700)
   if not os.path.exists(C_F) or not os.path.exists(K_F):
      create_self_signed_cert()

   try:
      opts, args = getopt.getopt(sys.argv[1:], "ho:v", ["help", "output="])
   except getopt.GetoptError as err:
      # print help information and exit:
      Log(str(err)) # will print something like "option -a not recognized"
      usage()
      sys.exit(2)
   for o, a in opts:
      if o in ['-d','--daemon']:
         # Ok, Lets detatch from the shell and begin
         daemonize('/dev/null','/var/log/ds-scheduler_slave.log','/var/log/ds-scheduler_slave.log')
      elif o in ['-h', '--help']:
         usage()
      else:
         assert False, "unhandled option"

   if os.getuid() != 0:
      Log("This daemon should run as root, exiting.")
      sys.exit(1)


   for o,p in opts:
      if o in ['-d','--daemon']:
         # Ok, Lets detatch from the shell and begin
         daemonize('/dev/null','/var/log/ds-scheduler_slave.log','/var/log/ds-scheduler_slave.log')
      elif o in ['-h', '--help']:
         usage()
   SocketServer.ThreadingTCPServer.allow_reuse_address = True
   server = Secure_ThreadingTCPServer((conf.bind_address, conf.agent_port), RequestHandler, C_F, K_F)
   server.serve_forever()

if __name__ == '__main__':
   main()
