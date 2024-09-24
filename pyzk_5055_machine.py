from zk import ZK
import time

ip = '10.20.1.95'
port = 5055
timeout = 180000

zk = ZK(ip, port=port, timeout=timeout, verbose=True)

try:
  print("Connecting to device ...")
  conn = zk.connect()
  print("Connection successful with device: {}".format(conn))
  print("Disabling device ...")
  conn.disable_device()
  print("Read records ...")
  initio = time.time()
  records = conn.get_attendance()
  finish = time.time()
  print("Time to read records: {}".format(finish - initio))
  print("Records: {}".format(records))
  print("Enabling device ...")
  conn.enable_device()
  print('Start live capture ...')
  live_capture = conn.live_capture()
  for capture in live_capture:
    print(capture)
  print("Disconnecting from device ...")
  conn.disconnect()

except Exception as e:
  if zk.is_connect:
    if not zk.is_enabled:
      zk.enable_device()
    zk.disconnect()
  print("Process failed: {}".format(e))

exit()