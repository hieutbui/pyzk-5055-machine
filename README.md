# pyzk-5055-machine

***I don't have access to ZKTeco development manual so carefully when implementing the code.***

The purpose of this repository is simple: If you have an attendance machine that has default connection port is 5xxx, it may work or will help you a bit for decoding the return bytes data.

The original version of core zk comes from this: [pyzk](https://github.com/fananimi/pyzk)

# API Usage

Create the ZK object and you will be ready to call api.

## Basic Usage

The following is an example code block how to use pyzk.

```python
from zk import ZK, const

conn = None
# create ZK instance
zk = ZK('192.168.1.201', port=4370, timeout=5, password=0, force_udp=False, ommit_ping=False)
try:
  # connect to device
  conn = zk.connect()
  # disable device, this method ensures no activity on the device while the process is run
  conn.disable_device()
  # another commands will be here!
  # Example: Get All Users
  users = conn.get_users()
  for user in users:
    privilege = 'User'
    if user.privilege == const.USER_ADMIN:
      privilege = 'Admin'
    print ('+ UID #{}'.format(user.uid))
    print ('  Name       : {}'.format(user.name))
    print ('  Privilege  : {}'.format(privilege))
    print ('  Password   : {}'.format(user.password))
    print ('  Group ID   : {}'.format(user.group_id))
    print ('  User  ID   : {}'.format(user.user_id))

  # re-enable device after all commands already executed
  conn.enable_device()
except Exception as e:
    print ("Process terminate : {}".format(e))
finally:
  if conn:
    conn.disconnect()
```

## Command List

* Connect/Disconnect

```python
conn = zk.connect()
conn.disconnect()
```

* Disable/Enable Connected Device

```python
# disable (lock) device, to ensure no user activity in device while some process run
conn.disable_device()
# re-enable the connected device and allow user activity in device again
conn.enable_device()
```

* User Operation

```python
# Get all users (will return list of User object)
users = conn.get_users()
```

* Attendance Record
```python
# Get attendances (will return list of all Attendance object)
attendances = conn.get_attendance()
```

* Live Capture!

```python
# live capture! (timeout at 10s)
for attendance in conn.live_capture():
  if attendance is None:
    # implement here timeout logic
    pass
  else:
    print (attendance) # Attendance object

    #if you need to break gracefully just set
    #   conn.end_live_capture = True
    #
    # On interactive mode,
    # use Ctrl+C to break gracefully
    # this way it restores timeout
    # and disables live capture
```

# Compatible devices

```
Firmware Version : Ver 6.60 Oct 25 2022
Platform         : AK3750WIFI_TFT
Default port     : 5055
```



### Latest tested (not really confirmed)

```
Firmware Version : Ver 6.60 Oct 25 2022
Platform         : AK3750WIFI_TFT
```

### Not Working (needs more tests, more information)

```

```

If you have another version tested and it worked, please inform me to update this list!
