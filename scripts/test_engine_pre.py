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

g_timeout = 15

def run_cert_cmd(base_dir,fname_log,cert_type,new_key=1,cmd_cert=None):
   if cmd_cert is None:
      cmd_cert = '%s/run_cert_%s.sh >> %s 2>&1 ' % (base_dir,cert_type,fname_log)
   else:
      cmd_cert = '%s/%s >> %s 2>&1 ' % (base_dir,cmd_cert,fname_log)
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

def run_rsa_cert(base_dir,fname_log):
   cmd_cert = '%s/run_rsa_ca.sh >> %s 2>&1' % (base_dir,fname_log)
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
      global g_timeout
      with open(self.fname_log,'a') as flog_client:
         print '** Running client command: %s **' % (self.cmd)
         p_client = pexpect.spawn(self.cmd,env=self.env,logfile=flog_client,timeout=g_timeout)
         if self.env['USE_EXAMPLE'] == '1':
            expect_str = 'Using cipher'
         else:
            expect_str = '---'

         try:
            print '** CLIENT: Waiting for prompt %s **' % (expect_str)
            self.mutex_expect.lock(p_client.expect,expect_str)
            print '** CLIENT: Got prompt %s **' % (expect_str)
         #except pexpect.TIMEOUT:
         #except pexpect.EOF:
         except:
            print '** ERROR: Exception at unlock in client location 0 **'
            self.exitstatus = 255
            return(0)
         self.mutex_expect.unlock()

         #
         # Client sends string
         #

         # Plain text string
         plain_text = 'hello world'
         expect_str = plain_text

         print '** CLIENT: Sending: %s **' % (expect_str)
         self.mutex_expect.lock(p_client.sendline,expect_str)
         print '** CLIENT: DONE Sending: %s **' % (expect_str)
         self.mutex_expect.unlock()

         # Server recognizes string
         #server_status = self.p_server.expect(plain_text)
         time.sleep(2)

         ### Client may have exited as this point in time

         # Client shows prompt of ciphered data
         print '** CLIENT: Waiting for %s **' % (expect_str)
         self.mutex_expect.lock(p_client.expect,expect_str)
         print '** CLIENT: DONE Waiting for %s **' % (expect_str)
         try:
            self.mutex_expect.unlock()
         except:
            print '** ERROR: Exception at unlock in client location 1 **'
            self.exitstatus = 255
            return (0)

         # Client shuts down
         expect_str = 'q'
         print '** CLIENT: Sending: %s **' % (expect_str)
         self.mutex_expect.lock(p_client.sendline,expect_str)
         print '** CLIENT: DONE Sending: %s **' % (expect_str)
         try:
            self.mutex_expect.unlock()
         except:
            print '** ERROR: Exception at unlock in client location 2 **'
            self.exitstatus = 255
            return (0)

         print '** After client quit **'
#      except:
#         print '** ERROR: client pexpect protocol failed'

      p_client.close(force=True)
      while p_client.isalive(): # Wait for child to exit gracefully
         pass

      time.sleep(1)

      if p_client.exitstatus is None:
         self.exitstatus = 255
      self.exitstatus = p_client.exitstatus
      #print '** p_client.exitstatus: %s' % (self.exitstatus)

      return (0)

def pkill_openssl():
   time.sleep(1)
   cmd = 'pkill openssl'
   print cmd
   os.system(cmd)
   time.sleep(1)
   cmd = 'ps aux | grep openssl'
   print cmd
   os.system(cmd)


def test_expect(client_cmd_lst,cmd_server,env_server,fname_log_server):
   # Spawn server
   flog_server = open(fname_log_server,'a')
   print '** Running server command: %s **' % (cmd_server)

   if debug:
      return (0,0)

   p_server = pexpect.spawn(cmd_server,env=env_server,logfile=flog_server,timeout=g_timeout)
   try:
      print '*** SERVER: Waiting for accept ***'
      mutex_expect.lock(p_server.expect,'ACCEPT')
      print '*** SERVER: got ACCEPT ***'
      mutex_expect.unlock()
   except:
      print '*** ERROR: No ACCEPT on server ***'

   # delay, waiting for server to come up?
   time.sleep(2)

   client_thread_lst = []
   for (cmd_client,fname_log_client,env_client) in client_cmd_lst:
      # A new thread needs to be created for each client
      client_thread = client_driver(env_client,fname_log_client,cmd_client)
      client_thread.start()
      client_thread_lst += [client_thread]

   # This code should execute only after all clients have exited
   # wait for all threads on client_thread_lst
   client_exitstatus = 0
   twait_client = 10
   for client_thread in client_thread_lst:
      print '*** SERVER: Waiting for client threads to exit ***'
      client_thread.join(twait_client)
      print '*** SERVER: p_client.exitstatus: %s ***' % (client_thread.exitstatus)
      if client_thread.exitstatus is None:
         client_exitstatus |= 255
      else:
         client_exitstatus |= client_thread.exitstatus

   try: 
      # Server retruns to ACCEPT prompt after receives msesages: DONE, shutting down SSL
      print '*** SERVER: Waiting for CONNECTION CLOSED ***'
      mutex_expect.lock(p_server.expect,'CONNECTION CLOSED')
      print '*** SERVER: got CONNECTION CLOSED ***'
      mutex_expect.unlock()

      print '*** SERVER: before server ctrl-D ***'
      mutex_expect.lock(p_server.sendcontrol,'d')
      mutex_expect.unlock()
      print '*** SERVER: after server ctrl-D ***'
   except:
      print '*** ERROR: No CONNECTION CLOSED on server ***'

   time.sleep(1)
   p_server.close(force=True)
   server_status = p_server.signalstatus
   if server_status is None:
      server_status = 255 # Indicate error
   while p_server.isalive():
      pass
   flog_server.close()

   # Hack - openssl process has at times seen to be still running even after the above shutdown sequence.  Try harder with OS commands.
   pkill_openssl()

   print 'SERVER: exitstatus: %s signalstatus: %s status: %s' % (p_server.exitstatus,
                                                                 p_server.signalstatus,
                                                                 p_server.status)

   with open(fname_log_server,'a') as flog_server:
      flog_server.write('EXITSTATUS_CLIENT: %d EXITSTATUS_SERVER: %d\n' % (client_exitstatus,server_status))

   return (client_exitstatus,server_status)

if __name__ == "__main__":
        base_dir = '.'
        pkill_openssl()
