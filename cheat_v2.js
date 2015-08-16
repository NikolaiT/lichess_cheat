/**
 * 
 * https://github.com/NikolaiT/lichess_cheat
 * 
 * Just copy paste this file into your browsers javascript console.
 * Make sure the cheat_server.py is running on your localhost before!
 * 
 * Author = Nikolai Tschacher
 * Date = Summer 2015
 * Contact = incolumitas.com
 */

(function() {
 
 var allMoves = '';
 var incrementTime = parseInt(/\+([0-9]+)/g.exec($('span.setup').text())[1]);
 var ply = -1;
 var uci = null;
 var playerColor = $('.cg-board').hasClass('orientation-black') ? 'black' : 'white';
 var debug = true;
 var movesBy = 'moves';

  function addEngineProposalClass() {
      $("<style>")
          .prop("type", "text/css")
          .html("\
          .engineProposal {\
              border-color: #FF4D4D;\
              border-width: 3px;\
              border-style: solid;\
          };\
          .enginePonderProposal {\
              border-color: #5CADFF;\
              border-width: 2px;\
              border-style: solid;\
          }")
          .appendTo("head");
  }
  
  function highlightEngineProposal(engineMove) {
      var bfrom = engineMove.best.slice(0, 2),
          bto = engineMove.best.slice(2, 4),
          pfrom = engineMove.ponder.slice(0, 2),
          pto = engineMove.ponder.slice(2, 4);
          
      $('.cg-square').removeClass('engineProposal');
      $('.cg-square').removeClass('enginePonderProposal');
      
      $('.cg-square.' + bfrom).addClass('engineProposal');
      $('.cg-square.' + bto).addClass('engineProposal');
      
      $('.cg-square.' + pfrom).addClass('enginePonderProposal');
      $('.cg-square.' + pto).addClass('enginePonderProposal');
  }

  function getLastMove() {
      // https://github.com/ornicar/lila/commit/372e492c16e88c21de6b063a059f9b66dc8b5c6a
      
      function getMove(s) { return s.match(/[a-h][0-8]/g); };
      
      try {
        var to = getMove($('.last-move.oc, .last-move.occupied').attr('class'));
        var from = getMove($('.last-move').not('.oc, .occupied').attr('class'));
      } catch (e) {
        return '';
      }
      
      return from+to;
  }
  
  function getRemainingTime() {
    var time = $('.clock_' + playerColor + ' .time').text();
    var minutes = parseInt(/^([0-9]*?):/g.exec(time)[1]);
    return minutes * 60 + parseInt(time.slice(-2));
  }

  function getLatestPositionAsFenByAPI() {
    var gameState = {ply: -1, posAsFen: null};

    $.ajax({
      dataType: 'json',
      url: 'http://en.lichess.org/api/game/'+ document.URL.split('.org/').slice(-1)[0] +'?with_moves=1&with_fens=1',
      async: false,
      success: function(game) {
        gameState.posAsFen = game.fens.slice(-1)[0];
        gameState.ply = parseInt(game.turns);
      }});

    return gameState;
  }

  function getEngineMoveBy(what) {
      var bestMoves = '',
          url = '';

      if (what === 'fen') {
        url = "http://localhost:8888/lastPosFen_" 
                + getLatestPositionAsFenByAPI().posAsFen + "_";
      } else if (what === 'moves') {
        url = "http://localhost:8888/allMoves/"
             + allMoves + "/incrementTime/"
             + incrementTime + "/remainingTime/"
             + getRemainingTime() + "/";
      }
      
      $.ajax({
        url: url,
        success: function(html) {
          bestMoves = html;
        },
        async:false
      });
      
      return {
        'best': bestMoves.slice(0, 4),
        'ponder': bestMoves.slice(5,9)
      };
  }
  
  function isMyTurn() {
      return (playerColor === 'white' && (ply % 2 === 0)) ||
          (playerColor === 'black' && (ply % 2 === 1));
  }
  

  function showEngineMove() {
      if (isMyTurn()) {
          engineMoves = getEngineMoveBy(movesBy);
          highlightEngineProposal(engineMoves);
      }
  }
  
  addEngineProposalClass();
  
  if (playerColor === 'black') {
    uci = '';
    ply++;
  }

  setInterval(function() {
      var lastMove = getLastMove();
      
      if (uci !== lastMove) {
        // new next move!
        uci = lastMove;
        ply++;
        allMoves += (' ' + uci);
        
        if (debug) {
          console.log(playerColor);
          console.log("My turn: " + isMyTurn());
          console.log(allMoves);
          console.log(ply);
          console.log(uci);
        }
        showEngineMove();
        
      }

  }, 75);

})();
  
