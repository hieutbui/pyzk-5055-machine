from zk import ZK
import time
import argparse
import sys
import traceback

class ArgsNameSpace(argparse.Namespace):
  address: str
  port: int
  timeout: int
  verbose: bool
  password: int | None
  live_capture: bool
  live_capture_timeout: int
  records: bool

parser = argparse.ArgumentParser(description='ZK 5055 Machine')
parser.add_argument('-a', '--address', type=str, help='Device IP Address [192.168.1.201]', default='192.168.1.201')
parser.add_argument('-p', '--port', type=int, help='Device connection port [5055]', default=5055)
parser.add_argument('-T', '--timeout', type=int, help='Device connection timeout, default [1000] seconds (0: disable timeout)', default=1000)
parser.add_argument('-v', '--verbose', action='store_true', help='Print debug information')
parser.add_argument('-P', '--password', type=int, help='Device code/password', default=None)
parser.add_argument('-l', '--live-capture', action="store_true", help='Live Event Capture')
parser.add_argument('-lt', '--live-capture-timeout', type=int, help='Live Event Capture timeout', default=10)
parser.add_argument('-r', '--records', action="store_true", help='Get attendance records')

arg = parser.parse_args(namespace=ArgsNameSpace())

zk = ZK(ip=arg.address, port=arg.port, timeout=arg.timeout, verbose=arg.verbose, password=arg.password)

conn = None

try:
  print("Connecting to device ...")
  conn = zk.connect()
  print("Connection successful with device: {}".format(conn))
  print("Disabling device ...")
  conn.disable_device()
  if arg.records:
    print("Read records ...")
    initio = time.time()
    records = conn.get_attendance()
    finish = time.time()
    print("Records: {}".format(records))
    print("Time to read records: {}".format(finish - initio))
  if arg.live_capture:
    print ('--- Live Capture! (press ctrl+C to break) ---')
    live_capture = conn.live_capture(new_timeout=arg.live_capture_timeout)
    for capture in live_capture:
      print(capture)
    print('--- capture End!---')
except Exception as e:
  print("Process failed: {}".format(e))
  print("Error: %s" % sys.exc_info()[0])
  print('-'*60)
  traceback.print_exc(file=sys.stdout)
  print('-'*60)
finally:
  if conn:
    if not conn.is_enabled:
      print("Enabling device ...")
      conn.enable_device()
    if conn.is_connect:
      print("Disconnecting ...")
      conn.disconnect()
    print("Connection closed")