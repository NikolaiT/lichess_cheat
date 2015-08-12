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
    return lichess.round.data.steps.slice(-1)[0];
}

function getFenOfLastPosition() {
    return lichess.round.data.steps.slice(-1)[0].fen;
}

function getAllMovesPlayed() {
    var moves = '';
    for (var i = 1; i < lichess.round.data.steps.length; i++) {
        moves += lichess.round.data.steps[i].uci + ' ';
    }
    return moves;
}

function getEngineMove(fen) {
    var myMove = '';
    
    $.ajax({
    url: "http://localhost:8888/lastPosFen_" + fen + "_",
    success: function(html) {
      myMove = html;
    },
    async:false
    });
    
    return myMove;
}

function getEngineMoveByAllMoves() {
    var myMove = '';
    
    $.ajax({
    url: "http://localhost:8888/allMoves_" + getAllMovesPlayed() + "_",
    success: function(html) {
      myMove = html;
    },
    async:false
    });
    
    return myMove;
}

function getPlayerColor() {
    return lichess.round.data.player.color;
}
    
function isMyTurn(lastMove) {
    return (getPlayerColor() === 'white' && (lastMove.ply % 2 === 0)) ||
        (getPlayerColor() === 'black' && (lastMove.ply % 2 === 1));
}

function highlightEngineProposal(engineMove) {
    var from = engineMove.slice(0, 2),
        to = engineMove.slice(2, 4);
        
    console.log('Highlithing move:' + engineMove);
    
    $('.cg-square').removeClass('engineProposal');
    $('.cg-square.' + from).addClass('engineProposal');
    $('.cg-square.' + to).addClass('engineProposal');
}

function showEngineMove(lastMove) {
    if (isMyTurn(lastMove)) {
        engineMove = getEngineMoveByAllMoves();
        highlightEngineProposal(engineMove);
    }
}


addEngineProposalClass();
var lm = {'ply': -1};

setInterval(function() {
    
    if (lm.ply !== getLastMove().ply) {
        // new next move!
        lm = getLastMove();
        showEngineMove(lm);
    }

}, 75);
