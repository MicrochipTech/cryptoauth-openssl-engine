#!/usr/bin/env python

import os
import sys
import subprocess
import pexpect
import re
import time
import signal
import threading
import mutex

debug = False
#debug = True

mutex_expect = mutex.mutex()

def run_cert_cmd(base_dir,cert_type,new_key=1,cmd_cert=None):
   if cmd_cert is None:
      cmd_cert = '%s/run_cert_%s.sh ' % (base_dir,cert_type)
   else:
      cmd_cert = '%s/%s ' % (base_dir,cmd_cert)
   my_env = os.environ.copy()
   my_env['NEW_KEY'] = '%d' % (new_key)
   print '** Running CERT command: %s' % (cmd_cert)
   child = pexpect.spawn(cmd_cert,env=my_env)
   child.logfile = sys.stdout
   child.expect('Enter PEM pass phrase:')
   child.sendline('1111')
   child.expect('Verifying - Enter PEM pass phrase:')
   child.sendline('1111')
   child.expect('Enter PEM pass phrase:')
   child.sendline('1111')               
   while child.isalive(): # Wait for child to exit gracefully
      pass
   child.close()

   print 'Exit status: %s %s' % (child.exitstatus,child.status)
   if child.exitstatus is not 0:
      print 'ERROR: Cert command %s FAILED' % (cmd_cert)
      sys.exit(child.exitstatus)

   return cmd_cert

def run_rsa_cert(base_dir):
   cmd_cert = '%s/run_rsa_ca.sh ' % (base_dir)
   print '** Running CERT command: %s' % (cmd_cert)
   if debug:
      return
   os.system(cmd_cert)

class client_driver(threading.Thread):
   def __init__(self,env,fname_log,cmd):
      threading.Thread.__init__(self)
      self.env = env
      self.fname_log = fname_log
      self.cmd = cmd
      #self.exitstatus = None
      self.exitstatus = 1
      self.mutex_expect = mutex_expect

   def run(self):
      with open(self.fname_log,'w') as flog_client:
         print '** Running client command: %s **' % (self.cmd)
         p_client = pexpect.spawn(self.cmd,env=self.env,logfile=flog_client)
#      try:
         # Plain text string
         plain_text = 'hello world'

         # Client sends string
         self.mutex_expect.lock(p_client.expect,'---')
         #p_client.expect('---')
         self.mutex_expect.unlock()

         self.mutex_expect.lock(p_client.sendline,plain_text)
         #p_client.sendline(plain_text)
         self.mutex_expect.unlock()

         # Server recognizes string
         #server_status = self.p_server.expect(plain_text)
         time.sleep(2)

         ### Client may have exited as this point in time

         # Client shows prompt of ciphered data
         self.mutex_expect.lock(p_client.expect,'rec->data')
         #p_client.expect('rec->data')
         try:
            self.mutex_expect.unlock()
         except:
            print '** ERROR: Exception at unlock in client **'

         # Client shuts down
         print 'before client ctrl-D'
##         self.mutex_expect.lock(p_client.sendcontrol,'d')
         self.mutex_expect.lock(p_client.sendline,'q')
         #p_client.sendcontrol('d')
         try:
            self.mutex_expect.unlock()
         except:
            print '** ERROR: Exception at unlock in client **'
         print 'after client ctrl-D'
#      except:
#         print '** ERROR: client pexpect protocol failed'

      p_client.close(force=True)
      while p_client.isalive(): # Wait for child to exit gracefully
         pass

      time.sleep(1)

      if p_client.exitstatus is None:
         self.exitstatus = 1
      self.exitstatus = p_client.exitstatus
      #print '** p_client.exitstatus: %s' % (self.exitstatus)

      return (0)

def test_expect(client_cmd_lst,cmd_server,env_server,fname_log_server):
   # Spawn server
   flog_server = open(fname_log_server,'w')
   print '** Running server command: %s **' % (cmd_server)

   if debug:
      return (0,0)

   p_server = pexpect.spawn(cmd_server,env=env_server,logfile=flog_server)
   try:
      mutex_expect.lock(p_server.expect,'ACCEPT')
      #p_server.expect('ACCEPT')
      mutex_expect.unlock()
   except:
      pass

   # delay, waiting for server to come up?
   time.sleep(2)

   client_thread_lst = []
   for (cmd_client,fname_log_client,env_client) in client_cmd_lst:
      # A new thread needs to be created for each client
      client_thread = client_driver(env_client,fname_log_client,cmd_client)
      client_thread.start()
      client_thread_lst += [client_thread]

   try: # BOZO - unclear to to relate this on a per server thread basis or else per socket basis
      # Server retruns to ACCEPT prompt after receives msesages: DONE, shutting down SSL
      mutex_expect.lock(p_server.expect,'CONNECTION CLOSED')
      #p_server.expect('CONNECTION CLOSED')
      mutex_expect.unlock()

      print 'before server ctrl-D'
      mutex_expect.lock(p_server.sendcontrol,'d')
      #p_server.sendcontrol('d')
      mutex_expect.unlock()
      print 'after server ctrl-D'
   except:
      pass

      #time.sleep(1)
      #p_server.kill(signal.SIGHUP)
      #time.sleep(1)
      #p_server.kill(signal.SIGTERM)
      #time.sleep(1)
      #p_server.kill(signal.SIGKILL)

   client_exitstatus = 0
   for client_thread in client_thread_lst:
      client_thread.join(5)
      print '** p_client.exitstatus: %s' % (client_thread.exitstatus)
      client_exitstatus |= client_thread.exitstatus

   # This code should execute only after all clients have exited
   # wait for all threads on client_thread_lst
   time.sleep(1)
   p_server.close(force=True)
   #p_server.close()
   server_status = p_server.signalstatus
   while p_server.isalive():
      pass
   flog_server.close()

   # Hack - openssl process has at times seen to be still running even after the above shutdown sequence.  Try harder with OS commands.
   time.sleep(1)
   cmd = 'pkill openssl'
   print cmd
   os.system(cmd)
   time.sleep(1)
   cmd = 'ps aux | grep openssl'
   print cmd
   os.system(cmd)

   print 'SERVER: exitstatus: %s signalstatus: %s status: %s' % (p_server.exitstatus,
                                                                 p_server.signalstatus,
                                                                 p_server.status)

   with open(fname_log_server,'a') as flog_server:
      flog_server.write('EXITSTATUS_CLIENT: %d EXITSTATUS_SERVER: %d\n' % (client_exitstatus,server_status))

   return (client_exitstatus,server_status)

if __name__ == "__main__":
        base_dir = '.'

