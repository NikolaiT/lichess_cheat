#!/usr/bin/env python3

# https://github.com/NikolaiT/lichess_cheat
# Implements a RESTful Api to the stockfish engine.
# You may call this RESTful API with a request as the follows:
# http://localhost:8888/allMoves/e2e4 e7e5/incrementTime/1/remainingTime/60/
# All times are in seconds.

__author__ = 'Nikolai Tschacher'
__contact__ = 'incolumitas.com'
__date__ = 'Summer 2015'

import string
import subprocess
import os
import time
import sys
import re
import random
import zipfile
import pprint

PY3 = sys.version_info[0] == 3

if PY3:
  from urllib.request import URLopener
  from urllib.parse import unquote
  from http.server import BaseHTTPRequestHandler, HTTPServer
  import socketserver
else:
  from urllib import URLopener, unquote
  from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
  import SocketServer

def gen_password(n=10):
  return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))

config = {
  'stockfish_download_link': 'https://stockfish.s3.amazonaws.com/stockfish-6-{}.zip',
	'stockfish_binary' : '', # the path to your local stockfish binary
  'pwd': os.path.dirname(os.path.realpath(__file__)),
  'debug': False,
  'thinking_time': 1,
  'max_thinking_time': 2, # in seconds
  'js_cheat_file': 'cheat_v2.js',
  'password': gen_password(),
}

def unzip(source_filename, dest_dir):
  """
  Taken from:
  http://stackoverflow.com/questions/12886768/how-to-unzip-file-in-python-on-all-oses
  """
  with zipfile.ZipFile(source_filename) as zf:
    for member in zf.infolist():
      # Path traversal defense copied from
      # http://hg.python.org/cpython/file/tip/Lib/http/server.py#l789
      words = member.filename.split('/')
      path = dest_dir
      for word in words[:-1]:
        drive, word = os.path.splitdrive(word)
        head, word = os.path.split(word)
        if word in (os.curdir, os.pardir, ''): continue
        path = os.path.join(path, word)
      zf.extract(member, path)

def install_stockfish():
  """
  Grabs the latest stockfish binary and installs it besides the script.
  """
  dl = config.get('stockfish_download_link')
  binary_path = ''
  
  if os.name == 'nt':
    dl = dl.format('win')
    binary_path = os.path.join(config.get('pwd'), 'stockfish/stockfish-6-win\\Windows\\stockfish-6-win\\Windows\\stockfish-6-64.exe')
  elif os.name == 'posix' and sys.platform.startswith('linux'):
    dl = dl.format('linux')
    binary_path = os.path.join(config.get('pwd'), 'stockfish/stockfish-6-linux/Linux/stockfish-6-linux/Linux/stockfish_6_x64')
  elif sys.platform.startswith('darwin'):
    dl = dl.format('mac')
    binary_path = os.path.join(config.get('pwd'), 'stockfish/stockfish-6-mac/Mac/stockfish-6-64')
  else:
    exit('System {} is not supported.'.format(os.name))
    
  if not os.path.exists(binary_path):
    save_in = os.path.join(config.get('pwd'), 'stockfish.zip')
    request = urllib.request.URLopener()
    request.retrieve(dl, save_in)
    unzip(save_in, os.path.join(config.get('pwd'), 'stockfish'))
    os.unlink(save_in)
    
    if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
      os.system('chmod +x {}'.format(binary_path))
  
  config['stockfish_binary'] = binary_path
  
  if config.get('debug', False):
    pprint.pprint(config)
  

def javascript_clipboard_widget():
  # from tkinter import Tk, Scrollbar, Text, mainloop

  # root = Tk()
  # S = Scrollbar(root)
  # T = Text(root, height=20, width=50)
  # S.pack(side=RIGHT, fill=Y)
  # T.pack(side=LEFT, fill=Y)
  # S.config(command=T.yview)
  # T.config(yscrollcommand=S.set)
  # T.insert(END, js_text)
  # mainloop()
  import webbrowser

  js_file = os.path.join(config['pwd'], config['js_cheat_file'])
  js_text = open(js_file, 'r').readlines()

  # replace with password generated
  newlines = []
  replacement = "  var passwordKey = '{}';\n".format(config['password'])
  for line in js_text:
    newlines.append(replacement if 'var passwordKey' in line else line)
  
  with open(js_file, 'wt') as f:
    f.write(''.join(newlines))

  webbrowser.open('file://' + js_file)
  

class StockfishEngine():
  """Implements all engine related stuff"""
  
  def __init__(self, stockfish_plays_white=True):
    """
    Sets the engine up.
    
    stockfish_plays_white determines whether stockfish is white or black. If 
    stockfish is white, it needs to make the first move.
    
    thinking_time controls how much time stockfish is given to calculate its moves.
    max_thinking_time determines the maximum thinking time the engine has.
    """
    self.max_thinking_time = config.get('max_thinking_time', 2)
    self.thinking_time = config.get('thinking_time', 1)
    self.stockfish_plays_white = stockfish_plays_white
    self.proc = None
    self.moves = []
    self.fen = ''
    
    self.init_stockfish()
    
  def get(self, poll=True, sleep_time=0):
    if poll:
      self.proc.stdin.write('isready\n')
    buf = ''
    while True:
      time.sleep(sleep_time)
      line = self.proc.stdout.readline().strip()
      buf += line
      if 'readyok' in line:
        return buf
      if 'bestmove' in line:
        return buf
 
  def init_stockfish(self):
    if os.path.exists(config['stockfish_binary']):
      self.proc = subprocess.Popen([config['stockfish_binary']], universal_newlines=True,
                  stdout=subprocess.PIPE, stdin=subprocess.PIPE)
   
      greeting = self.get()
      if not 'Stockfish' in greeting:
        raise ValueError('Couldnt execute stockfish')
   
      self.proc.stdin.write('uci\n')
      self.get()
      # stolen from https://github.com/brandonhsiao/lichess-bot/blob/master/server.py
      self.proc.stdin.write('ucinewgame\n')
      self.get()
      # some of theese options are not supported. Doesn't harm us...
      self.proc.stdin.write('setoption name Hash value 128\n')
      self.proc.stdin.write('setoption name Threads value 4\n')
      self.proc.stdin.write('setoption name Best Book Move value true\n')
      self.proc.stdin.write('setoption name Aggressiveness value 200\n')
      self.proc.stdin.write('setoption name Cowardice value 0\n')
      self.proc.stdin.write('setoption name Contempt Factor value 50\n')
    else:
      raise ValueError('No stockfish binary path given by {}'.format(config['stockfish_binary']))
    
  def whos_move_is_it(self):
    return 'white' if (len(self.moves) % 2 == 0) else 'black'
      
  def start_move_calculation(self, remaining_time=None, increment_time=None, stop_later=False):
    """
    When remaining_time and increment_time are given, the best move
    is calculated considering the remaining time. If not, the thinking_time
    given in the config is considered.
    """
    if remaining_time and increment_time:
      remaining_time, increment_time = int(remaining_time) * 1000, int(increment_time) * 1000
      if self.whos_move_is_it() == 'white':
        cmd = 'go wtime {} winc {}\n'.format(remaining_time, increment_time)
      else:
        cmd = 'go btime {} binc {}\n'.format(remaining_time, increment_time)
      
      self.proc.stdin.write(cmd)
      sleep_time = self.max_thinking_time
    else:
      self.proc.stdin.write('go infinite\n')
      sleep_time = self.thinking_time if self.max_thinking_time < self.thinking_time else self.max_thinking_time

    if not stop_later:
      try:
        time.sleep(float(sleep_time))
      except ValueError as ve:
        print(ve)
        sys.exit(0)

      return self.stop_move_calculation()

  def stop_move_calculation(self):
    self.proc.stdin.write('stop\n')
    out = self.get(poll=False)
    
    try:
      bestmove = re.search(r'bestmove\s(?P<move>[a-h][1-8][a-h][1-8])', out).group('move')
      ponder = re.search(r'ponder\s(?P<ponder>[a-h][1-8][a-h][1-8])', out).group('ponder')
    except AttributeError:
      return False

    return bestmove, ponder
 
  def newgame_stockfish(self, stockfish_plays_white=True, fen='',
              all_moves=None, remaining_time=None, increment_time=None, stop_later=False):
    self.stockfish_plays_white = stockfish_plays_white
    self.moves = []
    
    if fen:
      self.fen = fen
      self.proc.stdin.write('position fen {}\n'.format(fen))
      return self.start_move_calculation(remaining_time, increment_time)
      
    if all_moves is not None:
      self.moves = all_moves.split(' ')
      if all_moves:
        self.proc.stdin.write('position startpos moves {}\n'.format(all_moves))
      else:
        self.proc.stdin.write('position startpos\n')
      
      return self.start_move_calculation(remaining_time, increment_time, stop_later=stop_later)
      
  def quit_stockfish(self):
    self.proc.stdin.write('quit\n')
    self.proc.terminate()
  
  
class StockfishServer(BaseHTTPRequestHandler):
  
    def get_param(self, names, delimiter='/'):
      if not isinstance(names, tuple):
        raise ValueError('variable "names" must be a tuple')
      
      ns = {}
      for name in names:
        try:
          ns[name] = re.search(r'{name}{delimiter}(?P<{name}>[^{delimiter}]*?){delimiter}'.format(
            name=name,
            delimiter=delimiter), self.path).group(name)
        except Exception as e:
          ns[name] = None
      
      return ns
      
    def do_GET(self):
        params = {}
        best, ponder = '', ''
        
        if self.path.startswith('/lastPosFen_'):
          params = self.get_param(('lastPosFen', 'passwordKey'), delimiter='_')
          best, ponder = engine.newgame_stockfish(fen=unquote(params['lastPosFen']))
        elif self.path.startswith('/allMoves/'):
          params = self.get_param(('allMoves', 'remainingTime', 'incrementTime', 'passwordKey'))
          best, ponder = engine.newgame_stockfish(
                          all_moves=unquote(params['allMoves']),
                          remaining_time=params['remainingTime'],
                          increment_time=params['incrementTime'])

        if config.get('debug', False):
          pprint.pprint(params)
          print('Server Key: {}, Request Key: {}'.format(config['password'], params.get('passwordKey', '')))

        if params.get('passwordKey', '') == config['password']:
          self.send_response(200)
          self.send_header('Access-Control-Allow-Origin', '*')
          self.send_header('Content-type', 'text/html')
          self.end_headers()
          self.wfile.write(bytes(best + ' ' + ponder, "utf-8"))
        else:
          if config.get('debug', False):
            print('Invalid request without password. Blocking.')

def run(engine, server_class=HTTPServer, handler_class=StockfishServer):
    javascript_clipboard_widget()
    server_address = ('', 8888)
    httpd = server_class(server_address, handler_class)
    print('[+] Running CheatServer.py on {}:{}'.format(server_address[0], server_address[1]))
    httpd.engine = engine
    httpd.serve_forever()


install_stockfish()

if __name__ == '__main__':
  engine = StockfishEngine()
  run(engine)
