/*
  Stockfish, a UCI chess playing engine derived from Glaurung 2.1
  Copyright (C) 2004-2008 Tord Romstad (Glaurung author)
  Copyright (C) 2008-2015 Marco Costalba, Joona Kiiski, Tord Romstad

  Stockfish is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Stockfish is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SEARCH_H_INCLUDED
#define SEARCH_H_INCLUDED

#include <memory>  // For std::auto_ptr
#include <stack>
#include <vector>

#include "misc.h"
#include "position.h"
#include "types.h"

struct SplitPoint;

namespace Search {

/// Stack struct keeps track of the information we need to remember from nodes
/// shallower and deeper in the tree during the search. Each search thread has
/// its own array of Stack objects, indexed by the current ply.

struct Stack {
  SplitPoint* splitPoint;
  Move* pv;
  int ply;
  Move currentMove;
  Move ttMove;
  Move excludedMove;
  Move killers[2];
  Depth reduction;
  Value staticEval;
  bool skipEarlyPruning;
};

/// RootMove struct is used for moves at the root of the tree. For each root move
/// we store a score and a PV (really a refutation in the case of moves which
/// fail low). Score is normally set at -VALUE_INFINITE for all non-pv moves.

struct RootMove {

  RootMove(Move m) : score(-VALUE_INFINITE), previousScore(-VALUE_INFINITE), pv(1, m) {}

  bool operator<(const RootMove& m) const { return score > m.score; } // Ascending sort
  bool operator==(const Move& m) const { return pv[0] == m; }
  void insert_pv_in_tt(Position& pos);
  Move extract_ponder_from_tt(Position& pos);

  Value score;
  Value previousScore;
  std::vector<Move> pv;
};

typedef std::vector<RootMove> RootMoveVector;

/// LimitsType struct stores information sent by GUI about available time to
/// search the current move, maximum depth/time, if we are in analysis mode or
/// if we have to ponder while it's our opponent's turn to move.

struct LimitsType {

  LimitsType() { // Init explicitly due to broken value-initialization of non POD in MSVC
    nodes = time[WHITE] = time[BLACK] = inc[WHITE] = inc[BLACK] = movestogo =
    depth = movetime = mate = infinite = ponder = 0;
  }

  bool use_time_management() const {
    return !(mate | movetime | depth | nodes | infinite);
  }

  std::vector<Move> searchmoves;
  int time[COLOR_NB], inc[COLOR_NB], movestogo, depth, movetime, mate, infinite, ponder;
  int64_t nodes;
};

/// The SignalsType struct stores volatile flags updated during the search
/// typically in an async fashion e.g. to stop the search by the GUI.

struct SignalsType {
  bool stop, stopOnPonderhit, firstRootMove, failedLowAtRoot;
};

typedef std::auto_ptr<std::stack<StateInfo> > StateStackPtr;

extern volatile SignalsType Signals;
extern LimitsType Limits;
extern RootMoveVector RootMoves;
extern Position RootPos;
extern Time::point SearchTime;
extern StateStackPtr SetupStates;

void init();
void think();
template<bool Root> uint64_t perft(Position& pos, Depth depth);

} // namespace Search

#endif // #ifndef SEARCH_H_INCLUDED
