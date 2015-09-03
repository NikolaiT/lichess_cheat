#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from proxy import WebSocketProxy, HttpProxy, main
from cheat_server import run
import zlib


def hexdump(src, length=16, sep='.'):
    """
    Taken from https://gist.github.com/ImmortalPC/c340564823f283fe530b.

    @brief Return {src} in hex dump.
    @param[in] length   {Int} Nb Bytes by row.
    @param[in] sep      {Char} For the text part, {sep} will be used for non ASCII char.
    @return {Str} The hexdump

    @note Full support for python2 and python3 !
    """
    result = []

    # Python3 support
    try:
        xrange(0,1)
    except NameError:
        xrange = range

    for i in xrange(0, len(src), length):
        subSrc = src[i:i+length]
        hexa = ''
        isMiddle = False
        for h in xrange(0,len(subSrc)):
            if h == length/2:
                hexa += ' '
            h = subSrc[h]
            if not isinstance(h, int):
                h = ord(h)
            h = hex(h).replace('0x','')
            if len(h) == 1:
                h = '0'+h
            hexa += h+' '
        hexa = hexa.strip(' ')
        text = ''
        for c in subSrc:
            if not isinstance(c, int):
                c = ord(c)
            if 0x20 <= c < 0x7F:
                text += chr(c)
            else:
                text += sep
        result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text))

    print('\n'.join(result))


class LichessCheat(object):
    """

    Typical WebSocket communication between browser and lichess server:

    Opponent makes a move:

    SERVER -> CLIENT
    WebSocket Frame: fin = 1, opcode = TEXT_FRAME, mask = 0, maskign_key: , payload_length = 274, 
    payload = {"v":1,"t":"move","d":{"uci":"e2e4","san":"e4","fen":"rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR","ply":1,"clock":{"white":300,"black":300},"dests":{"b8":"a6c6","g8":"f6h6","h7":"h6h5","d7":"d6d5","g7":"g6g5","c7":"c6c5","f7":"f6f5","b7":"b6b5","e7":"e6e5","a7":"a6a5"}}}
        

    !!! this move is triggered by our browser UI 
    CLIENT -> SERVER
    WebSocket Frame: fin = 1, opcode = TEXT_FRAME, mask = 1, maskign_key: �0D�, payload_length = 182, 
    payload = {"t":"move","d":{"from":"d7","to":"d5","b":1,"lag":43}}

    !!! the server sends back our own move with more info such as the possible replies and the fen string of the position
    SERVER -> CLIENT
    WebSocket Frame: fin = 1, opcode = TEXT_FRAME, mask = 0, maskign_key: , payload_length = 322, 
    payload = {"v":2,"t":"move","d":{"uci":"d7d5","san":"d5","fen":"rnbqkbnr/ppp1pppp/8/3p4/4P3/8/PPPP1PPP/RNBQKBNR","ply":2,"clock":{"white":300,"black":300},"dests":{"a2":"a3a4","g1":"f3h3e2","d1":"e2f3g4h5","e1":"e2","d2":"d3d4","b1":"a3c3","e4":"e5d5","f1":"e2d3c4b5a6","h2":"h3h4","b2":"b3b4","f2":"f3f4","c2":"c3c4","g2":"g3g4"}}}

    !!! and the move from the opponent is also received with the same additional information
    SERVER -> CLIENT
    WebSocket Frame: fin = 1, opcode = TEXT_FRAME, mask = 0, maskign_key: , payload_length = 322, 
    payload = {"v":3,"t":"move","d":{"uci":"e4d5","san":"exd5","fen":"rnbqkbnr/ppp1pppp/8/3P4/8/8/PPPP1PPP/RNBQKBNR","ply":3,"clock":{"white":303.3190002441406,"black":300},"dests":{"b8":"d7a6c6","c8":"d7e6f5g4h3","g8":"f6h6","h7":"h6h5","e8":"d7","g7":"g6g5","c7":"c6c5","d8":"d7d6d5","f7":"f6f5","b7":"b6b5","e7":"e6e5","a7":"a6a5"}}}
    """

    GAME_STATE_AWAITING_START = 1
    GAME_STATE_STARTED = 2
    GAME_STATE_ENDED = 3

    def __init__(self, debug=True):
        self.moves = []
        self.ply = 0
        self.last_pos_fen = ''
        self.debug = debug
        self.game_state = self.GAME_STATE_AWAITING_START
        self.playing_white = None

        self.engine = run()

        # always start calculating when creating this object in the
        # case the we start the game
        self.engine.newgame_stockfish(all_moves=' '.join(self.moves), stop_later=True)
        self.calculating = True

    def get_engine_move(self):
        engine_move = self.engine.newgame_stockfish(all_moves=' '.join(self.moves))

        if self.debug:
            print('EngineMove: {}'.format(str(engine_move)))

        return engine_move[0]

    def parse_json(self, s):
        """
        Returns an object from the json string or None.
        """
        try:
            return json.loads(s)
        except Exception as e:
            print('Cannot parse json data: {}. Exception: {}'.format(s, str(e)))
            return None

    def is_my_move(self):
        return self.playing_white and (self.ply % 2 == 0) or\
                not self.playing_white and (self.ply % 2 == 1)


    def on_send_message(self, frame, original_data):
        if 'from' in frame.unmasked_payload and 'to' in frame.unmasked_payload:
            if self.game_state == self.GAME_STATE_AWAITING_START:
                self.playing_white = True
                self.game_state = self.GAME_STATE_STARTED
            # we detect an outgoing move triggered by our UI
            # and we need to change it to the
            # engine move.
            move_obj = self.parse_json(frame.unmasked_payload)

            if move_obj:
                if self.calculating:
                    em = self.engine.stop_move_calculation()[0]
                    self.calculating = False 
                    new_payload = frame.unmasked_payload.replace(move_obj['d']['from'], em[:2])
                    new_payload = new_payload.replace(move_obj['d']['to'], em[2:4])

                    if self.debug:
                        print('Engine Move: {}'.format(em))

                    # frame.update_frame(new_payload)

                    bs = frame.to_bytes()
                    return bs

    def on_receive_message(self, frame):
        if '"uci"' in frame.payload:
            if self.game_state == self.GAME_STATE_AWAITING_START:
                self.playing_white = False
                self.game_state = self.GAME_STATE_STARTED

            move_obj = self.parse_json(frame.unmasked_payload)
            if move_obj:
                self.moves.append(move_obj['d']['uci'])
                self.ply = int(move_obj['d']['ply'])

                if self.debug:
                    print('Ply: {}, IsMyMove: {}, Moves: {}'.format(self.ply, self.is_my_move(), self.moves))

                if self.is_my_move():
                    self.engine.newgame_stockfish(all_moves=' '.join(self.moves), stop_later=True)
                    self.calculating = True


class LichessModifyJavascript(object):
    """
    Updates
    """

    def __init__(self):
        self.inject_js = '''
if (c.isPlayerTurn(this.data)) {
    setTimeout(function() {
        $.ajax({
            url: "http://localhost:8888/stopCalculation",
            success: function(html) {
                alert(html);
            }
        });
    }, 1000);
}
'''.replace('\n', '').replace('    ', ' ').strip()

        self.needle = 'this.apiMove=function(e){'

        self.compressor = zlib.decompressobj(16+zlib.MAX_WBITS)


    def on_response(self, request, response):
        if response.get_header('content-type') == 'application/javascript' and response.get_header('content-encoding') == 'gzip':
            js = self.compressor.decompress(response.body)
            new_js = js.replace(self.needle, self.needle + self.inject_js)
            response.body = new_js
            response.raw = response.build(del_headers=['transfer-encoding', 'content-encoding'])

            print(response)

            return response

    def await_parsed_response(self, request):
        return 'lichess.round.min.js' in request.url.path

# add the lichess cheat to modify websocket frames
WebSocketProxy.plugin = LichessCheat()

# and add the plugin to modify the JS
HttpProxy.plugin = LichessModifyJavascript()

if __name__ == '__main__':
    main()