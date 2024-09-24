class Attendance(object):
  def __init__(self, user_id, timestamp) -> None:
    self.user_id = user_id
    self.timestamp = timestamp

  def __str__(self) -> str:
    return f'"attendance": {{"user_id": {self.user_id}, "timestamp": "{self.timestamp}"}}'

  def __repr__(self) -> str:
    return f'"attendance": {{"user_id": {self.user_id}, "timestamp": "{self.timestamp}"}}'
  
class LiveAttendance(object):
  def __init__(self, user_id, timestamp, status, punch=0, uid=0):
    self.uid = uid # not really used any more
    self.user_id = user_id
    self.timestamp = timestamp
    self.status = status
    self.punch = punch

  def __str__(self):
    return f'"live_attendance": {{"user_id": {self.user_id}, "timestamp": "{self.timestamp}", "status": "{self.status}", "punch": {self.punch}}}'

  def __repr__(self):
    return f'"live_attendance": {{"user_id": {self.user_id}, "timestamp": "{self.timestamp}", "status": "{self.status}", "punch": {self.punch}}}'