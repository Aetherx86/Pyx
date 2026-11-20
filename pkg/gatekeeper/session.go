package gatekeeper

import (
	"strings"
	"time"
)

// SessionState tracks PostgreSQL connection/transaction-scoped safety parameters
// such as lock_timeout across individual statements and multi-statement batches.
type SessionState struct {
	InTransaction         bool
	HasSessionLockTimeout bool
	SessionLockTimeout    time.Duration
	HasLocalLockTimeout   bool
	LocalLockTimeout      time.Duration
}

// NewSessionState initializes a clean PostgreSQL connection session state.
func NewSessionState() *SessionState {
	return &SessionState{}
}

// Clone returns an independent shallow copy of SessionState for speculative evaluation.
func (s *SessionState) Clone() *SessionState {
	if s == nil {
		return NewSessionState()
	}
	cp := *s
	return &cp
}

// EffectiveLockTimeout returns the currently active lock_timeout and whether it was
// explicitly configured in the session or current transaction/batch.
func (s *SessionState) EffectiveLockTimeout() (d time.Duration, configured bool) {
	if s == nil {
		return 0, false
	}
	if s.HasLocalLockTimeout {
		return s.LocalLockTimeout, true
	}
	if s.HasSessionLockTimeout {
		return s.SessionLockTimeout, true
	}
	return 0, false
}

// ResetLocal clears transaction-local parameter overrides (invoked on COMMIT/ROLLBACK
// or when the backend signals ReadyForQuery('I')).
func (s *SessionState) ResetLocal() {
	if s == nil {
		return
	}
	s.HasLocalLockTimeout = false
	s.LocalLockTimeout = 0
}

// ApplySQL parses sql and applies any transaction or lock_timeout state transitions.
func (s *SessionState) ApplySQL(sql string) {
	if s == nil {
		return
	}
	for _, stmt := range LexStatements(sql) {
		s.ApplyTokens(stmt.Tokens)
	}
}

// ApplyTokens updates SessionState based on a single lexed statement's tokens.
func (s *SessionState) ApplyTokens(tokens []Token) {
	if s == nil || len(tokens) == 0 {
		return
	}
	first := tokens[0]
	if first.Kind != TokWord {
		return
	}

	switch first.Upper {
	case "BEGIN":
		s.InTransaction = true
		return

	case "START":
		if len(tokens) >= 2 && tokens[1].Kind == TokWord && tokens[1].Upper == "TRANSACTION" {
			s.InTransaction = true
		}
		return

	case "COMMIT", "END", "ABORT":
		s.InTransaction = false
		s.ResetLocal()
		return

	case "ROLLBACK":
		// ROLLBACK TO [SAVEPOINT] <name> keeps the transaction open.
		if len(tokens) >= 2 && tokens[1].Kind == TokWord && tokens[1].Upper == "TO" {
			return
		}
		s.InTransaction = false
		s.ResetLocal()
		return

	case "RESET":
		if len(tokens) >= 2 && tokens[1].Kind == TokWord {
			target := tokens[1].Upper
			if target == "LOCK_TIMEOUT" || target == "ALL" {
				s.HasLocalLockTimeout = false
				s.LocalLockTimeout = 0
				s.HasSessionLockTimeout = false
				s.SessionLockTimeout = 0
			}
		}
		return

	case "SET":
		s.applySetLockTimeout(tokens)
		return

	case "SELECT":
		s.applySetConfig(tokens)
		return
	}
}

func (s *SessionState) applySetLockTimeout(tokens []Token) {
	// Syntax: SET [SESSION | LOCAL] lock_timeout { TO | = } { value | DEFAULT }
	i := 1
	isLocal := false
	if i < len(tokens) && tokens[i].Kind == TokWord {
		if tokens[i].Upper == "LOCAL" {
			isLocal = true
			i++
		} else if tokens[i].Upper == "SESSION" {
			i++
		}
	}
	if i >= len(tokens) {
		return
	}
	param := tokens[i]
	if (param.Kind != TokWord && param.Kind != TokIdent) || !strings.EqualFold(param.Raw, "lock_timeout") {
		return
	}
	i++
	if i >= len(tokens) {
		return
	}
	if (tokens[i].Kind == TokOp && tokens[i].Raw == "=") || (tokens[i].Kind == TokWord && tokens[i].Upper == "TO") {
		i++
	} else {
		return
	}
	if i >= len(tokens) {
		return
	}

	valTok := tokens[i]
	var dur time.Duration
	var ok bool
	if valTok.Kind == TokWord && valTok.Upper == "DEFAULT" {
		dur, ok = 0, true
	} else if valTok.Kind == TokString || valTok.Kind == TokNumber {
		dur, ok = ParsePGDuration(valTok.Raw)
	}
	if !ok {
		return
	}

	if isLocal {
		s.HasLocalLockTimeout = true
		s.LocalLockTimeout = dur
	} else {
		s.HasSessionLockTimeout = true
		s.SessionLockTimeout = dur
		// SET SESSION overrides any active local override in the current statement stream.
		s.HasLocalLockTimeout = false
		s.LocalLockTimeout = 0
	}
}

func (s *SessionState) applySetConfig(tokens []Token) {
	// Look for SELECT [pg_catalog.]set_config('lock_timeout', '<val>', <is_local>)
	for i := 1; i+6 < len(tokens); i++ {
		if tokens[i].Kind == TokWord && tokens[i].Upper == "SET_CONFIG" && tokens[i+1].Kind == TokLParen {
			arg1 := tokens[i+2]
			if arg1.Kind != TokString || !strings.EqualFold(arg1.Raw, "lock_timeout") {
				continue
			}
			if tokens[i+3].Kind != TokComma {
				continue
			}
			arg2 := tokens[i+4]
			if arg2.Kind != TokString && arg2.Kind != TokNumber {
				continue
			}
			dur, ok := ParsePGDuration(arg2.Raw)
			if !ok {
				continue
			}
			isLocal := false
			if i+6 < len(tokens) && tokens[i+5].Kind == TokComma {
				arg3 := tokens[i+6]
				v := strings.ToLower(arg3.Raw)
				if v == "true" || v == "t" || v == "1" || v == "on" {
					isLocal = true
				}
			}
			if isLocal {
				s.HasLocalLockTimeout = true
				s.LocalLockTimeout = dur
			} else {
				s.HasSessionLockTimeout = true
				s.SessionLockTimeout = dur
				s.HasLocalLockTimeout = false
				s.LocalLockTimeout = 0
			}
			return
		}
	}
}
