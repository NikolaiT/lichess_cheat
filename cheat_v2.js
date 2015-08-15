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
      
      function getMove(s) { return s.match(/[a-h][0-8]/g); };
      
      try {
        var to = getMove($('.cg-square.last-move.occupied').attr('class'));
        var from = getMove($('.cg-square.last-move').not('.occupied').attr('class'));
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

  function getEngineMoveByAllMoves() {
      var bestMoves = '';
      
      $.ajax({
        // /allMoves/e2e4 e7e5/incrementTime/1/remainingTime/60/
      url: "http://localhost:8888/allMoves/" + allMoves + "/incrementTime/" + incrementTime + "/remainingTime/" + getRemainingTime() + "/",
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
          engineMoves = getEngineMoveByAllMoves();
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
  
