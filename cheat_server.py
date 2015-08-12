#!/usr/bin/env python3

__author__ = 'Nikolai Tschacher'
__date__ = 'Summer 2015'

import subprocess
import os
import time
import sys
import re
import random
import urllib.request
from urllib.parse import unquote
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
import zipfile
import pprint

config = {
  'stockfish_download_link': 'https://stockfish.s3.amazonaws.com/stockfish-6-{}.zip',
	'stockfish_binary' : '', # the path to your local stockfish binary
  'pwd': os.path.dirname(os.path.realpath(__file__)),
  'debug': False
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
    dl = dl.format('windows')
    binary_path = os.path.join(config.get('pwd'), 'Windows\\stockfish-6-64.exe')
  elif os.name == 'posix' and sys.platform.startswith('linux'):
    dl = dl.format('linux')
    binary_path = os.path.join(config.get('pwd'), 'stockfish-6-linux/Linux/stockfish-6-linux/Linux/stockfish_6_x64')
  elif sys.platform.startswith('darwin'):
    dl = dl.format('mac')
    binary_path = os.path.join(config.get('pwd'), 'stockfish-6-mac/Mac/stockfish-6-64')
  else:
    exit('System {} is not supported.'.format(os.name))
    
  if not os.path.exists(binary_path):
    save_in = os.path.join(config.get('pwd'), 'stockfish.zip')
    request = urllib.request.URLopener()
    request.retrieve(dl, save_in)
    unzip(save_in, config.get('pwd'))
    os.unlink(save_in)
    
    if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
      os.system('chmod +x {}'.format(binary_path))
  
  config['stockfish_binary'] = binary_path
  
  if config.get('debug', False):
    pprint.pprint(config)
  
  
class StockfishEngine():
  """Implements all engine related stuff"""
  
  def __init__(self, stockfish_plays_white=True, thinking_time=1):
    """
    Sets the engine up.
    
    stockfish_plays_white determines whether stockfish is white or black. If 
    stockfish is white, it needs to make the first move.
    
    thinking_time controls how much time stockfish is given to calculate its moves.
    """
    self.thinking_time = thinking_time
    self.stockfish_plays_white = stockfish_plays_white
    self.proc = None
    self.moves = []
    install_stockfish()
    self.init_stockfish()
    
  def get(self, poll=True):
    if poll:
      self.proc.stdin.write('isready\n')
    buf = ''
    while True:
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
   
      greeting = self.get(self.proc)
      if not 'Stockfish' in greeting:
        raise ValueError('Couldnt execute stockfish')
   
      self.proc.stdin.write('uci\n')
      self.get()
      # stolen from https://github.com/brandonhsiao/lichess-bot/blob/master/server.py
      self.proc.stdin.write('ucinewgame\n')
      self.get()
      self.proc.stdin.write('setoption name Hash value 128\n')
      self.proc.stdin.write('setoption name Threads value 4\n')
      self.proc.stdin.write('setoption name Best Book Move value true\n')
      self.proc.stdin.write('setoption name Aggressiveness value 200\n')
      self.proc.stdin.write('setoption name Cowardice value 0\n')
      self.proc.stdin.write('setoption name Contempt Factor value 50\n')
    else:
      raise ValueError('No stockfish binary path given')
      
 
  def make_move(self, move=None, thinking_time=1):
    if thinking_time != self.thinking_time:
      self.thinking_time = thinking_time
    
    if move:
      self.moves.append(move)
      
    if self.moves:
      cmd = 'position startpos moves {}\n'.format(' '.join(self.moves))
      self.proc.stdin.write(cmd)
      
    return self.start_move_calculation()
    
      
  def start_move_calculation(self):      
    self.proc.stdin.write('go infinite\n')
    try:
      time.sleep(float(self.thinking_time))
    except ValueError as ve:
      print(ve)
      sys.exit(0)
    self.proc.stdin.write('stop\n')
    out = self.get(False)
    try:
      bestmove = re.search(r'bestmove\s(?P<move>[a-h][1-8][a-h][1-8])', out).group('move')
      ponder = re.search(r'ponder\s(?P<ponder>[a-h][1-8][a-h][1-8])', out).group('ponder')
    except AttributeError:
      return False
      
    self.moves.append(bestmove)
    
    return bestmove
 
 
  def newgame_stockfish(self, stockfish_plays_white=True, fen='', all_moves=None):
    self.stockfish_plays_white = stockfish_plays_white
    self.moves = []
    
    if fen:
      self.proc.stdin.write('position fen {}\n'.format(fen))
      return self.start_move_calculation()
      
    if all_moves is not None:
      if all_moves:
        self.proc.stdin.write('position startpos moves {}\n'.format(all_moves))
      else:
        self.proc.stdin.write('position startpos\n')
      
      return self.start_move_calculation()
      
    if self.stockfish_plays_white:
      return self.make_move()
      
   
  def quit_stockfish(self):
    self.proc.stdin.write('quit\n')
    self.proc.terminate()
  
  
class StockfishServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        if self.path.startswith('/newgame_'):
          playing_white = self.path.startswith('/newgame_white')
          move = engine.newgame_stockfish(stockfish_plays_white=playing_white)
          if not move:
            move = ''
          self.wfile.write(bytes(move, "utf-8"))
        elif self.path.startswith('/moved_'):
          regex = re.compile(r'/moved_(?P<move>\w*?)_')
          move = regex.match(self.path).group('move')
          m = engine.make_move(move=move)
          self.wfile.write(bytes(m, "utf-8"))
        elif self.path.startswith('/lastPosFen_'):
          regex = re.compile(r'/lastPosFen_(?P<fen>.*)_')
          fen = regex.match(self.path).group('fen')
          move = engine.newgame_stockfish(fen=unquote(fen))
          self.wfile.write(bytes(move, "utf-8"))
        elif self.path.startswith('/allMoves_'):
          regex = re.compile(r'/allMoves_(?P<allMoves>.*)_')
          all_moves = regex.match(self.path).group('allMoves')
          move = engine.newgame_stockfish(all_moves=unquote(all_moves))
          self.wfile.write(bytes(move, "utf-8"))

def run(engine, server_class=HTTPServer, handler_class=StockfishServer):
    server_address = ('', 8888)
    httpd = server_class(server_address, handler_class)
    print('[+] Running CheatServer.py on {}:{}'.format(server_address[0], server_address[1]))
    httpd.engine = engine
    httpd.serve_forever()


if __name__ == '__main__':
  install_stockfish()
  engine = StockfishEngine()
  run(engine)
