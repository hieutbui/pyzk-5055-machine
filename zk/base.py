import codecs
from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM, timeout
from struct import unpack, pack
from typing import Iterator, Optional

from datetime import datetime
from .exception import ZKErrorConnection, ZKErrorResponse, ZKNetworkError
from .user import User
from .attendance import Attendance, LiveAttendance
from . import const

def make_commkey(key, session_id, ticks=50):
  """
  take a password and session_id and scramble them to send to the machine.
  copied from commpro.c - MakeKey
  """
  key = int(key)
  session_id = int(session_id)
  k = 0
  for i in range(32):
    if (key & (1 << i)):
      k = (k << 1 | 1)
    else:
      k = k << 1
  k += session_id

  k = pack(b'I', k)
  k = unpack(b'BBBB', k)
  k = pack(
    b'BBBB',
    k[0] ^ ord('Z'),
    k[1] ^ ord('K'),
    k[2] ^ ord('S'),
    k[3] ^ ord('O'),
  )
  k = unpack(b'HH', k)
  k = pack(b'HH', k[1], k[0])

  B = 0xff & ticks
  k = unpack(b'BBBB', k)
  k = pack(
    b'BBBB',
    k[0] ^ B,
    k[1] ^ B,
    B,
    k[3] ^ B,
  )
  return k

class ZK_helper(object):
  """
  ZK helper class
  """

  def __init__(self, ip, port=4370):
    """
    Construct a new 'ZK_helper' object.
    """
    self.address = (ip, port)
    self.ip = ip
    self.port = port

  def test_ping(self):
    """
    Returns True if host responds to a ping request

    :return: bool
    """
    import subprocess, platform
    # Ping parameters as function of OS
    ping_str = "-n 1" if  platform.system().lower()=="windows" else "-c 1 -W 5"
    args = "ping " + " " + ping_str + " " + self.ip
    need_sh = False if  platform.system().lower()=="windows" else True
    # Ping
    return subprocess.call(
      args,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      shell=need_sh,
    ) == 0

  def test_tcp(self):
    """
    test TCP connection
    """

    self.client = socket(AF_INET, SOCK_STREAM)
    self.client.settimeout(10)
    res = self.client.connect_ex(self.address)
    self.client.close()
    return res

class ZK(object):
  """
  ZK main class
  """

  def __init__(self, ip, port=4370, timeout=60, password=0, force_udp=False, ommit_ping=False, verbose=False, encoding='UTF-8') -> None:
    """
    Construct a new 'ZK' object.

    :param ip: machine's IP address
    :param port: machine's port
    :param timeout: timeout number
    :param password: passint
    :param force_udp: use UDP connection
    :param ommit_ping: check ip using ping before connect
    :param verbose: showing log while run the commands
    :param encoding: user encoding
    """
    User.encoding = encoding
    self.__address = (ip, port)
    self.__sock = socket(AF_INET, SOCK_DGRAM)
    self.__sock.settimeout(timeout)
    self.__timeout = timeout
    self.__password = password # passint
    self.__session_id = 0
    self.__reply_id = const.USHRT_MAX - 1
    self.__data_recv = None
    self.__data = None

    self.is_connect = False
    self.is_enabled = True
    self.helper = ZK_helper(ip, port)
    self.force_udp = force_udp
    self.ommit_ping = ommit_ping
    self.verbose = verbose
    self.encoding = encoding
    self.tcp = not force_udp
    self.users = 0
    self.next_uid = 1
    self.next_user_id = '1'
    self.user_packet_size = 28 # default zk6
    self.end_live_capture = False

  def __str__(self):
    """
    for debug
    """
    return "ZK %s://%s:%s" % ("tcp" if self.tcp else "udp", self.__address[0], self.__address[1])

  def __create_socket(self):
    if self.tcp:
      self.__sock = socket(AF_INET, SOCK_STREAM)
      self.__sock.settimeout(self.__timeout)
      self.__sock.connect_ex(self.__address)
    else:
      self.__sock = socket(AF_INET, SOCK_DGRAM)
      self.__sock.settimeout(self.__timeout)

  def connect(self):
    """
    connect to the device

    :return: bool
    """
    self.end_live_capture = False
    if not self.ommit_ping and not self.helper.test_ping():
      raise ZKNetworkError("can't reach device (ping %s)" % self.__address[0])
    if not self.force_udp and self.helper.test_tcp() == 0:
      self.user_packet_size = 72 # default zk8
    self.__create_socket()
    self.__session_id = 0
    self.__reply_id = const.USHRT_MAX - 1
    cmd_response = self.__send_command(const.CMD_CONNECT)
    self.__session_id = self.__header[2]
    if cmd_response.get('code') == const.CMD_ACK_UNAUTH:
      if self.verbose: print ("try auth")
      command_string = make_commkey(self.__password, self.__session_id)
      cmd_response = self.__send_command(const.CMD_AUTH, command_string)
    if cmd_response.get('status'):
      self.is_connect = True
      return self
    else:
      if cmd_response["code"] == const.CMD_ACK_UNAUTH:
        raise ZKErrorResponse("Unauthenticated")
      if self.verbose: print ("connect err response {} ".format(cmd_response["code"]))
      raise ZKErrorResponse("Invalid response: Can't connect")

  def disconnect(self):
    """
    disconnect from the connected device

    :return: bool
    """
    cmd_response = self.__send_command(const.CMD_EXIT)
    if cmd_response.get('status'):
      self.is_connect = False
      if self.__sock:
        self.__sock.close()
      return True
    else:
      raise ZKErrorResponse("can't disconnect")

  def enable_device(self):
    """
    re-enable the connected device and allow user activity in device again

    :return: bool
    """
    cmd_response = self.__send_command(const.CMD_ENABLEDEVICE)
    if cmd_response.get('status'):
      self.is_enabled = True
      return True
    else:
      raise ZKErrorResponse("Can't enable device")

  def disable_device(self):
    """
    disable (lock) device, to ensure no user activity in device while some process run

    :return: bool
    """
    cmd_response = self.__send_command(const.CMD_DISABLEDEVICE)
    if cmd_response.get('status'):
      self.is_enabled = False
      return True
    else:
      raise ZKErrorResponse("Can't disable device")
  
  def __create_tcp_top(self, packet):
    """
    witch the complete packet set top header
    """
    length = len(packet)
    top = pack('<HHI', const.MACHINE_PREPARE_DATA_1, const.MACHINE_PREPARE_DATA_2, length)
    return top + packet
  
  def __test_tcp_top(self, packet):
    """
    return size!
    """
    if len(packet)<=8:
      return 0
    tcp_header = unpack('<HHI', packet[:8])
    if tcp_header[0] == const.MACHINE_PREPARE_DATA_1 and tcp_header[1] == const.MACHINE_PREPARE_DATA_2:
      return tcp_header[2]
    return 0

  def __receive_tcp_data(self, data_recv, size):
    """ data_recv, raw tcp packet
    must analyze tcp_length

    must return data, broken
    """
    data = []
    tcp_length = self.__test_tcp_top(data_recv)
    if self.verbose: print("tcp_length {}, size {}".format(tcp_length, size))
    if tcp_length <= 0:
      if self.verbose: print("Incorrect tcp packet")
      return None, b""
    if (tcp_length - 8) < size:
      if self.verbose: print("tcp length too small... retrying")
      resp, bh = self.__receive_tcp_data(data_recv, tcp_length - 8)
      data.append(resp)
      size -= len(resp)
      if self.verbose: print("new tcp DATA packet to fill missing {}".format(size))
      data_recv = bh + self.__sock.recv(size + 16 )
      if self.verbose: print("new tcp DATA starting with {} bytes".format(len(data_recv)))
      resp, bh = self.__receive_tcp_data(data_recv, size)
      data.append(resp)
      if self.verbose: print("for missing {} received {} with extra {}".format(size, len(resp), len(bh)))
      return b''.join(data), bh
    received = len(data_recv)
    if self.verbose: print("received {}, size {}".format(received, size))
    response = unpack('HHHH', data_recv[8:16])[0]
    if received >= (size + 32):
      if response == const.CMD_DATA:
        resp = data_recv[16 : size + 16]
        if self.verbose: print("resp complete len {}".format(len(resp)))
        return resp, data_recv[size + 16:]
      else:
        if self.verbose: print("incorrect response!!! {}".format(response))
        return None, b""
    else:
      if self.verbose: print("try DATA incomplete (actual valid {})".format(received-16))
      data.append(data_recv[16 : size + 16 ])
      size -= received - 16
      broken_header = b""
      if size < 0:
        broken_header = data_recv[size:]
        if self.verbose: print("broken", (broken_header).encode('hex'))
      if size > 0:
        data_recv = self.__receive_raw_data(size)
        data.append(data_recv)
      return b''.join(data), broken_header
  
  def __create_checksum(self, p):
    """
    Calculates the checksum of the packet to be sent to the time clock
    Copied from zkemsdk.c
    """
    l = len(p)
    checksum = 0
    while l > 1:
      checksum += unpack('H', pack('BB', p[0], p[1]))[0]
      p = p[2:]
      if checksum > const.USHRT_MAX:
        checksum -= const.USHRT_MAX
      l -= 2
    if l:
      checksum = checksum + p[-1]

    while checksum > const.USHRT_MAX:
      checksum -= const.USHRT_MAX

    checksum = ~checksum

    while checksum < 0:
      checksum += const.USHRT_MAX

    return pack('H', checksum)

  def __create_header(self, command, command_string, session_id, reply_id):
    """
    Puts a the parts that make up a packet together and packs them into a byte string
    """
    buf = pack('<4H', command, 0, session_id, reply_id) + command_string
    buf = unpack('8B' + '%sB' % len(command_string), buf)
    checksum = unpack('H', self.__create_checksum(buf))[0]
    reply_id += 1
    if reply_id >= const.USHRT_MAX:
      reply_id -= const.USHRT_MAX

    buf = pack('<4H', command, checksum, session_id, reply_id)
    return buf + command_string

  def __send_command(self, command, command_string=b'', response_size=8):
    """
    send command to the terminal
    """
    if command not in [const.CMD_CONNECT, const.CMD_AUTH] and not self.is_connect:
      raise ZKErrorConnection("instance are not connected.")

    buf = self.__create_header(command, command_string, self.__session_id, self.__reply_id)
    try:
      if self.tcp:
        top = self.__create_tcp_top(buf)
        self.__sock.send(top)
        self.__tcp_data_recv = self.__sock.recv(response_size + 8)
        self.__tcp_length = self.__test_tcp_top(self.__tcp_data_recv)
        if self.__tcp_length == 0:
          raise ZKNetworkError("TCP packet invalid")
        self.__header = unpack('<4H', self.__tcp_data_recv[8:16])
        self.__data_recv = self.__tcp_data_recv[8:]
      else:
        self.__sock.sendto(buf, self.__address)
        self.__data_recv = self.__sock.recv(response_size)
        self.__header = unpack('<4H', self.__data_recv[:8])
    except Exception as e:
      raise ZKNetworkError(str(e))

    self.__response = self.__header[0]
    self.__reply_id = self.__header[3]
    self.__data = self.__data_recv[8:]
    if self.__response in [const.CMD_ACK_OK, const.CMD_PREPARE_DATA, const.CMD_DATA]:
      return {
        'status': True,
        'code': self.__response
      }
    return {
      'status': False,
      'code': self.__response
    }
  
  def __get_data_size(self):
    """
    Checks a returned packet to see if it returned CMD_PREPARE_DATA,
    indicating that data packets are to be sent

    Returns the amount of bytes that are going to be sent
    """
    response = self.__response
    if response == const.CMD_PREPARE_DATA:
      size = unpack('I', self.__data[:4])[0]
      return size
    else:
      return 0
  
  def __receive_raw_data(self, size):
    """ partial data ? """
    data = []
    if self.verbose: print("expecting {} bytes raw data".format(size))
    while size > 0:
      data_recv = self.__sock.recv(size)
      received = len(data_recv)
      if self.verbose: print("partial recv {}".format(received))
      if received < 100 and self.verbose: print("   recv {}".format(codecs.encode(data_recv, 'hex')))
      data.append(data_recv)
      size -= received
      if self.verbose: print("still need {}".format(size))
    return b''.join(data)

  def __receive_chunk(self):
    """ receive a chunk """
    if self.__response == const.CMD_DATA:
      if self.tcp:
        if self.verbose: print("_rc_DATA! is {} bytes, tcp length is {}".format(len(self.__data), self.__tcp_length))
        if len(self.__data) < (self.__tcp_length - 8):
          need = (self.__tcp_length - 8) - len(self.__data)
          if self.verbose: print("need more data: {}".format(need))
          more_data = self.__receive_raw_data(need)
          return b''.join([self.__data, more_data])
        else:
          if self.verbose: print("Enough data")
          return self.__data
      else:
        if self.verbose: print("_rc len is {}".format(len(self.__data)))
        return self.__data
    elif self.__response == const.CMD_PREPARE_DATA:
      data = []
      size = self.__get_data_size()
      if self.verbose: print("receive chunk: prepare data size is {}".format(size))
      if self.tcp:
        if len(self.__data) >= (8 + size):
          data_recv = self.__data[8:]
        else:
          data_recv = self.__data[8:] + self.__sock.recv(size + 32)
        resp, broken_header = self.__receive_tcp_data(data_recv, size)
        data.append(resp)
        # get CMD_ACK_OK
        if len(broken_header) < 16:
          data_recv = broken_header + self.__sock.recv(16)
        else:
          data_recv = broken_header
        if len(data_recv) < 16:
          print("trying to complete broken ACK %s /16" % len(data_recv))
          if self.verbose: print(data_recv.encode('hex'))
          data_recv += self.__sock.recv(16 - len(data_recv)) #TODO: CHECK HERE_!
        if not self.__test_tcp_top(data_recv):
          if self.verbose: print("invalid chunk tcp ACK OK")
          return None
        response = unpack('HHHH', data_recv[8:16])[0]
        if response == const.CMD_ACK_OK:
          if self.verbose: print("chunk tcp ACK OK!")
          return b''.join(data)
        if self.verbose: print("bad response %s" % data_recv)
        if self.verbose: print(codecs.encode(data,'hex'))
        return None

      while True:
        data_recv = self.__sock.recv(1024+8)
        response = unpack('<4H', data_recv[:8])[0]
        if self.verbose: print("# packet response is: {}".format(response))
        if response == const.CMD_DATA:
          data.append(data_recv[8:])
          size -= 1024
        elif response == const.CMD_ACK_OK:
          break
        else:
          if self.verbose: print("broken!")
          break
        if self.verbose: print("still needs %s" % size)
      return b''.join(data)
    else:
      if self.verbose: print("invalid response %s" % self.__response)
      return None
  
  def __read_chunk(self, start, size):
    """
    read a chunk from buffer
    """
    for _retries in range(3):
      command = const._CMD_READ_BUFFER
      command_string = pack('<ii', start, size)
      if self.tcp:
        response_size = size + 32
      else:
        response_size = 1024 + 8
      cmd_response = self.__send_command(command, command_string, response_size)
      data = self.__receive_chunk()
      if data is not None:
        return data
    else:
      raise ZKErrorResponse("can't read chunk %i:[%i]" % (start, size))
  
  def __ack_ok(self):
    """
    event ack ok
    """
    buf = self.__create_header(const.CMD_ACK_OK, b'', self.__session_id, const.USHRT_MAX - 1)
    try:
      if self.tcp:
        top = self.__create_tcp_top(buf)
        self.__sock.send(top)
      else:
        self.__sock.sendto(buf, self.__address)
    except Exception as e:
      raise ZKNetworkError(str(e))
  
  def free_data(self):
    """
    clear buffer

    :return: bool
    """
    command = const.CMD_FREE_DATA
    cmd_response = self.__send_command(command)
    if cmd_response.get('status'):
      return True
    else:
      raise ZKErrorResponse("can't free data")

  def read_with_buffer(self, command, fct=0 ,ext=0):
    """
    Test read info with buffered command (ZK6: 1503)
    """
    if self.tcp:
      MAX_CHUNK = 0xFFc0
    else:
      MAX_CHUNK = 16 * 1024
    command_string = pack('<bhii', 1, command, fct, ext)
    if self.verbose: print("rwb cs", command_string)
    response_size = 1024
    data = []
    start = 0
    cmd_response = self.__send_command(const._CMD_PREPARE_BUFFER, command_string, response_size)
    if not cmd_response.get('status'):
      raise ZKErrorResponse("RWB Not supported")
    if cmd_response['code'] == const.CMD_DATA:
      if self.tcp:
        if self.verbose: print("DATA! is {} bytes, tcp length is {}".format(len(self.__data), self.__tcp_length))
        if len(self.__data) < (self.__tcp_length - 8):
          need = (self.__tcp_length - 8) - len(self.__data)
          if self.verbose: print("need more data: {}".format(need))
          more_data = self.__receive_raw_data(need)
          return b''.join([self.__data, more_data]), len(self.__data) + len(more_data)
        else:
          if self.verbose: print("Enough data")
          size = len(self.__data)
          return self.__data, size
      else:
        size = len(self.__data)
        return self.__data, size
    size = unpack('I', self.__data[1:5])[0]
    if self.verbose: print("size fill be %i" % size)
    remain = size % MAX_CHUNK
    packets = (size-remain) // MAX_CHUNK # should be size /16k
    if self.verbose: print("rwb: #{} packets of max {} bytes, and extra {} bytes remain".format(packets, MAX_CHUNK, remain))
    for _wlk in range(packets):
      data.append(self.__read_chunk(start,MAX_CHUNK))
      start += MAX_CHUNK
    if remain:
      data.append(self.__read_chunk(start, remain))
      start += remain
    self.free_data()
    if self.verbose: print("_read w/chunk %i bytes" % start)
    return b''.join(data), start
    
  def get_attendance(self) -> list[Attendance]:
    """
    return attendance record

    :return: List of Attendance object
    """
    attendances = [Attendance]
    first_line_length = 21
    middle_line_length = 22
    last_line_length = 5
    attendance_data, size = self.read_with_buffer(const.CMD_ATTLOG_RRQ)

    position = 0

    first_line = attendance_data[position:position + first_line_length]
    attendances.append(self.decodeAttendance(first_line))

    position += first_line_length

    while len(attendance_data) - position > last_line_length:
      attendance_line = attendance_data[position:position + middle_line_length]
      attendances.append(self.decodeAttendance(attendance_line))
      position += middle_line_length

    return attendances
  
  def decodeAttendance(self, attendance_buffer: bytes) -> Attendance:
    user_id = self.getUserIdFromBuffer(attendance_buffer)
    timestamp = self.parseTimeToDate(attendance_buffer[-4:])

    return Attendance(user_id, timestamp)

  def getUserIdFromBuffer(self, attendance_buffer: bytes) -> str:
    if len(attendance_buffer) == 21:
      start_index = 6
    else:
      start_index = 7
    
    extracted_from_start = attendance_buffer[start_index:]

    first_null_index = extracted_from_start.index(0)

    return extracted_from_start[:first_null_index].decode('utf-8')
  
  def parseTimeToDate(self, time: bytes) -> datetime:
    t = unpack('I', time)[0]

    seconds = t % 60
    remaining_seconds = t // 60

    minutes = remaining_seconds % 60
    remaining_minutes = remaining_seconds // 60

    hour = remaining_minutes % 24
    remaining_hours = remaining_minutes // 24

    total_days = remaining_hours

    year_component = total_days // (12 * 31)
    year = year_component + 2000

    days_after_year = total_days % (12 * 31)
    month_component = days_after_year // 31
    month = month_component + 1

    day_component = days_after_year % 31
    day = day_component + 1

    date = datetime(year, month, day, hour, minutes, seconds)

    return date
  
  def read_sizes(self):
    """
    read the memory ussage
    """
    command = const.CMD_GET_FREE_SIZES
    response_size = 1024
    cmd_response = self.__send_command(command,b'', response_size)
    if cmd_response.get('status'):
      if self.verbose: print(codecs.encode(self.__data,'hex'))
      size = len(self.__data)
      if len(self.__data) >= 80:
        fields = unpack('20i', self.__data[:80])
        self.users = fields[4]
        self.__data = self.__data[80:]
      if len(self.__data) >= 12: #face info
        fields = unpack('3i', self.__data[:12]) #dirty hack! we need more information
      return True
    else:
      raise ZKErrorResponse("can't read sizes")
  
  def get_users(self):
    """
    :return: list of User object
    """
    self.read_sizes()
    if self.users == 0:
      self.next_uid = 1
      self.next_user_id='1'
      return []
    users = []
    max_uid = 0
    userdata, size = self.read_with_buffer(const.CMD_USERTEMP_RRQ, const.FCT_USER)
    if self.verbose: print("user size {} (= {})".format(size, len(userdata)))
    if size <= 4:
      print("WRN: missing user data")
      return []
    total_size = unpack("I",userdata[:4])[0]
    self.user_packet_size = total_size / self.users
    if not self.user_packet_size in [28, 72]:
      if self.verbose: print("WRN packet size would be  %i" % self.user_packet_size)
    userdata = userdata[4:]
    if self.user_packet_size == 28:
      while len(userdata) >= 28:
        uid, privilege, password, name, card, group_id, timezone, user_id = unpack('<HB5s8sIxBhI',userdata.ljust(28, b'\x00')[:28])
        if uid > max_uid: max_uid = uid
        password = (password.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
        name = (name.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
        group_id = str(group_id)
        user_id = str(user_id)
        #TODO: check card value and find in ver8
        if not name:
          name = "NN-%s" % user_id
        user = User(uid, name, privilege, password, group_id, user_id, card)
        users.append(user)
        if self.verbose: print("[6]user:",uid, privilege, password, name, card, group_id, timezone, user_id)
        userdata = userdata[28:]
    else:
      while len(userdata) >= 72:
        uid, privilege, password, name, card, group_id, user_id = unpack('<HB8s24sIx7sx24s', userdata.ljust(72, b'\x00')[:72])
        password = (password.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
        name = (name.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
        group_id = (group_id.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
        user_id = (user_id.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
        if uid > max_uid: max_uid = uid
        if not name:
          name = "NN-%s" % user_id
        user = User(uid, name, privilege, password, group_id, user_id, card)
        users.append(user)
        userdata = userdata[72:]
    max_uid += 1
    self.next_uid = max_uid
    self.next_user_id = str(max_uid)
    while True:
      if any(u for u in users if u.user_id == self.next_user_id):
        max_uid += 1
        self.next_user_id = str(max_uid)
      else:
        break
    return users

  def cancel_capture(self):
    """
    cancel capturing finger

    :return: bool
    """
    command = const.CMD_CANCELCAPTURE
    cmd_response = self.__send_command(command)
    return bool(cmd_response.get('status'))
  
  def reg_event(self, flags):
    """
    reg events
    """
    command = const.CMD_REG_EVENT
    command_string = pack ("I", flags)
    cmd_response = self.__send_command(command, command_string)
    if not cmd_response.get('status'):
      raise ZKErrorResponse("cant' reg events %i" % flags)
  
  def __decode_timehex(self, timehex):
    """
    timehex string of six bytes
    """
    year, month, day, hour, minute, second = unpack("6B", timehex)
    year += 2000
    d = datetime(year, month, day, hour, minute, second)
    return d
  
  def live_capture(self, new_timeout=10) -> Iterator[Optional[LiveAttendance]]:
    """
    try live capture of events

    :return: Iterator of LiveAttendance object or None
    """
    was_enabled = self.is_enabled
    users = self.get_users()
    self.cancel_capture()
    # self.verify_user()
    if not self.is_enabled:
      self.enable_device()
    if self.verbose: print ("start live_capture")
    self.reg_event(const.EF_ATTLOG)
    self.__sock.settimeout(new_timeout)
    self.end_live_capture = False
    while not self.end_live_capture:
      try:
        if self.verbose: print ("esperando event")
        data_recv = self.__sock.recv(1032)
        self.__ack_ok()
        if self.tcp:
          size = unpack('<HHI', data_recv[:8])[2]
          header = unpack('HHHH', data_recv[8:16])
          data = data_recv[16:]
        else:
          size = len(data_recv)
          header = unpack('<4H', data_recv[:8])
          data = data_recv[8:]
        if not header[0] == const.CMD_REG_EVENT:
          if self.verbose: print("not event! %x" % header[0])
          continue
        if not len(data):
          if self.verbose: print ("empty")
          continue
        while len(data) >= 10:
          if len(data) == 10:
            user_id, status, punch, timehex = unpack('<HBB6s', data)
            data = data[10:]
          elif len(data) == 12:
            user_id, status, punch, timehex = unpack('<IBB6s', data)
            data = data[12:]
          elif len(data) == 14:
            user_id, status, punch, timehex, _other = unpack('<HBB6s4s', data)
            data = data[14:]
          elif len(data) == 32:
            user_id,  status, punch, timehex = unpack('<24sBB6s', data[:32])
            data = data[32:]
          elif len(data) == 36:
            user_id,  status, punch, timehex, _other = unpack('<24sBB6s4s', data[:36])
            data = data[36:]
          elif len(data) == 37:
            user_id,  status, punch, timehex, _other = unpack('<24sBB6s5s', data[:37])
            data = data[37:]
          elif len(data) >= 52:
            user_id,  status, punch, timehex, _other = unpack('<24sBB6s20s', data[:52])
            data = data[52:]
          if isinstance(user_id, int):
            user_id = str(user_id)
          else:
            user_id = (user_id.split(b'\x00')[0]).decode(errors='ignore')
          timestamp = self.__decode_timehex(timehex)
          tuser = list(filter(lambda x: x.user_id == user_id, users))
          if not tuser:
            uid = int(user_id)
          else:
            uid = tuser[0].uid
          yield LiveAttendance(user_id, timestamp, status, punch, uid)
      except timeout:
        if self.verbose: print ("time out")
        yield None # return to keep watching
      except (KeyboardInterrupt, SystemExit):
        if self.verbose: print ("break")
        break
    if self.verbose: print ("exit gracefully")
    self.__sock.settimeout(self.__timeout)
    self.reg_event(0)
    if not was_enabled:
      self.disable_device()