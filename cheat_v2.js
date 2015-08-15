(function() {
 
 var allMoves = '';
 var ply = -1;
 var uci = '';
 var playerColor = $('.cg-board').hasClass('orientation-black') ? 'black' : 'white';
 var debug = true;

  function addEngineProposalClass() {
      $("<style>")
          .prop("type", "text/css")
          .html("\
          .engineProposal {\
              border-color: red;\
              border-width: 3px;\
              border-style: solid;\
          }")
          .appendTo("head");
  }

  function getLastMove() {
      
      function getMove(s) { return s.match(/[a-h][0-8]/g); };
      
      try {
        var to = getMove($('.cg-square.last-move.occupied').attr('class'));
        var from = getMove($('.cg-square.last-move').attr('class'));
      } catch (e) {
        return '';
      }
      
      return from+to;
  }
  
  function getEngineMoveByAllMoves() {
      var myMove = '';
      
      $.ajax({
      url: "http://localhost:8888/allMoves_" + allMoves + "_",
      success: function(html) {
        myMove = html;
      },
      async:false
      });
      
      return myMove;
  }
  
  function isMyTurn() {
      return (playerColor === 'white' && (ply % 2 === 0)) ||
          (playerColor === 'black' && (ply % 2 === 1));
  }
  
  function highlightEngineProposal(engineMove) {
      var from = engineMove.slice(0, 2),
          to = engineMove.slice(2, 4);
          
      $('.cg-square').removeClass('engineProposal');
      $('.cg-square.' + from).addClass('engineProposal');
      $('.cg-square.' + to).addClass('engineProposal');
  }

  function showEngineMove() {
      if (isMyTurn()) {
          engineMove = getEngineMoveByAllMoves();
          highlightEngineProposal(engineMove);
          allMoves += (' ' + engineMove);
      } else {
        allMoves += (' ' + uci);
      }
  }
  
  addEngineProposalClass();

  setInterval(function() {
      var lastMove = getLastMove();
      
      if (uci !== lastMove) {
      
        if (debug) {
          console.log(allMoves);
          console.log(ply);
          console.log(uci);
        }
          
        // new next move!
        uci = lastMove;
        ply++;

        showEngineMove();
      }

  }, 75);

})();
