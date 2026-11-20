package gatekeeper

import (
	"strconv"
	"strings"
	"time"
	"unicode"
)

// TokenKind classifies lexical tokens extracted from PostgreSQL SQL input.
type TokenKind int

const (
	TokWord   TokenKind = iota // Unquoted keyword or identifier
	TokIdent                   // Double-quoted identifier
	TokString                  // Single-quoted or dollar-quoted string literal
	TokNumber                  // Numeric literal
	TokOp                      // Operator (=, <>, !=, <=, >=, ::, etc.)
	TokLParen                  // (
	TokRParen                  // )
	TokComma                   // ,
	TokSemi                    // ;
	TokDot                     // .
	TokParam                   // Positional parameter ($1, $2, ...)
)

// Token represents a single PostgreSQL lexical token with 1-based line tracking.
type Token struct {
	Kind  TokenKind
	Raw   string
	Upper string
	Line  int
}

// Statement represents a single top-level SQL statement separated by semicolons.
type Statement struct {
	Index  int // 1-based statement index within the batch/file
	Line   int // 1-based starting line of the first token
	Tokens []Token
}

// LexStatements tokenizes PostgreSQL SQL input, stripping line comments (--),
// nested block comments (/* /* ... */ */), and preserving string literals,
// dollar-quoted strings, and double-quoted identifiers as distinct tokens,
// then splits the stream into top-level semicolon-delimited statements.
func LexStatements(sql string) []Statement {
	tokens := lexTokens(sql)
	if len(tokens) == 0 {
		return nil
	}

	var stmts []Statement
	var cur []Token
	parenDepth := 0
	stmtIndex := 0

	flush := func() {
		if len(cur) == 0 {
			return
		}
		stmtIndex++
		stmts = append(stmts, Statement{
			Index:  stmtIndex,
			Line:   cur[0].Line,
			Tokens: cur,
		})
		cur = nil
	}

	for _, tok := range tokens {
		switch tok.Kind {
		case TokLParen:
			parenDepth++
			cur = append(cur, tok)
		case TokRParen:
			if parenDepth > 0 {
				parenDepth--
			}
			cur = append(cur, tok)
		case TokSemi:
			if parenDepth == 0 {
				flush()
			} else {
				cur = append(cur, tok)
			}
		default:
			cur = append(cur, tok)
		}
	}
	flush()
	return stmts
}

func lexTokens(sql string) []Token {
	var tokens []Token
	n := len(sql)
	i := 0
	line := 1

	for i < n {
		ch := sql[i]

		// Whitespace
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' {
			if ch == '\n' {
				line++
			}
			i++
			continue
		}

		// Single-line comment: -- ... \n
		if ch == '-' && i+1 < n && sql[i+1] == '-' {
			i += 2
			for i < n && sql[i] != '\n' {
				i++
			}
			continue
		}

		// Nested block comment: /* ... /* ... */ ... */
		if ch == '/' && i+1 < n && sql[i+1] == '*' {
			depth := 1
			i += 2
			for i < n && depth > 0 {
				if sql[i] == '\n' {
					line++
					i++
					continue
				}
				if sql[i] == '/' && i+1 < n && sql[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if sql[i] == '*' && i+1 < n && sql[i+1] == '/' {
					depth--
					i += 2
					continue
				}
				i++
			}
			continue
		}

		// Escape string literal: E'...' or e'...'
		if (ch == 'E' || ch == 'e') && i+1 < n && sql[i+1] == '\'' {
			startLine := line
			i += 2
			var sb strings.Builder
			for i < n {
				c := sql[i]
				if c == '\n' {
					line++
				}
				if c == '\\' && i+1 < n {
					next := sql[i+1]
					if next == '\n' {
						line++
					}
					sb.WriteByte(next)
					i += 2
					continue
				}
				if c == '\'' {
					if i+1 < n && sql[i+1] == '\'' {
						sb.WriteByte('\'')
						i += 2
						continue
					}
					i++
					break
				}
				sb.WriteByte(c)
				i++
			}
			val := sb.String()
			tokens = append(tokens, Token{Kind: TokString, Raw: val, Upper: strings.ToUpper(val), Line: startLine})
			continue
		}

		// Standard single-quoted string: '...'
		if ch == '\'' {
			startLine := line
			i++
			var sb strings.Builder
			for i < n {
				c := sql[i]
				if c == '\n' {
					line++
				}
				if c == '\'' {
					if i+1 < n && sql[i+1] == '\'' {
						sb.WriteByte('\'')
						i += 2
						continue
					}
					i++
					break
				}
				sb.WriteByte(c)
				i++
			}
			val := sb.String()
			tokens = append(tokens, Token{Kind: TokString, Raw: val, Upper: strings.ToUpper(val), Line: startLine})
			continue
		}

		// Double-quoted identifier: "..."
		if ch == '"' {
			startLine := line
			i++
			var sb strings.Builder
			for i < n {
				c := sql[i]
				if c == '\n' {
					line++
				}
				if c == '"' {
					if i+1 < n && sql[i+1] == '"' {
						sb.WriteByte('"')
						i += 2
						continue
					}
					i++
					break
				}
				sb.WriteByte(c)
				i++
			}
			val := sb.String()
			tokens = append(tokens, Token{Kind: TokIdent, Raw: val, Upper: strings.ToUpper(val), Line: startLine})
			continue
		}

		// Dollar-quoted string ($tag$...$tag$) or positional parameter ($1)
		if ch == '$' {
			startLine := line
			if tag, tagLen, ok := matchDollarTag(sql[i:]); ok {
				i += tagLen
				contentStart := i
				closed := false
				for i < n {
					if strings.HasPrefix(sql[i:], tag) {
						val := sql[contentStart:i]
						i += len(tag)
						tokens = append(tokens, Token{Kind: TokString, Raw: val, Upper: strings.ToUpper(val), Line: startLine})
						closed = true
						break
					}
					if sql[i] == '\n' {
						line++
					}
					i++
				}
				if !closed {
					// Unterminated dollar-quoted literal consumes to EOF
					val := sql[contentStart:]
					tokens = append(tokens, Token{Kind: TokString, Raw: val, Upper: strings.ToUpper(val), Line: startLine})
				}
				continue
			}
			if i+1 < n && isASCIIDigit(sql[i+1]) {
				j := i + 1
				for j < n && isASCIIDigit(sql[j]) {
					j++
				}
				raw := sql[i:j]
				tokens = append(tokens, Token{Kind: TokParam, Raw: raw, Upper: raw, Line: startLine})
				i = j
				continue
			}
			tokens = append(tokens, Token{Kind: TokOp, Raw: "$", Upper: "$", Line: startLine})
			i++
			continue
		}

		// Single-char structural punctuation
		switch ch {
		case '(':
			tokens = append(tokens, Token{Kind: TokLParen, Raw: "(", Upper: "(", Line: line})
			i++
			continue
		case ')':
			tokens = append(tokens, Token{Kind: TokRParen, Raw: ")", Upper: ")", Line: line})
			i++
			continue
		case ',':
			tokens = append(tokens, Token{Kind: TokComma, Raw: ",", Upper: ",", Line: line})
			i++
			continue
		case ';':
			tokens = append(tokens, Token{Kind: TokSemi, Raw: ";", Upper: ";", Line: line})
			i++
			continue
		case '.':
			tokens = append(tokens, Token{Kind: TokDot, Raw: ".", Upper: ".", Line: line})
			i++
			continue
		}

		// Numeric literal
		if isASCIIDigit(ch) {
			start := i
			for i < n && isASCIIDigit(sql[i]) {
				i++
			}
			if i < n && sql[i] == '.' && i+1 < n && isASCIIDigit(sql[i+1]) {
				i++
				for i < n && isASCIIDigit(sql[i]) {
					i++
				}
			}
			raw := sql[start:i]
			tokens = append(tokens, Token{Kind: TokNumber, Raw: raw, Upper: raw, Line: line})
			continue
		}

		// Unquoted keyword or identifier
		if isIdentStart(ch) {
			start := i
			i++
			for i < n && isIdentCont(sql[i]) {
				i++
			}
			raw := sql[start:i]
			tokens = append(tokens, Token{Kind: TokWord, Raw: raw, Upper: strings.ToUpper(raw), Line: line})
			continue
		}

		// Multi-char operators
		if i+1 < n {
			two := sql[i : i+2]
			switch two {
			case "<>", "!=", "<=", ">=", "::", "||", "->":
				tokens = append(tokens, Token{Kind: TokOp, Raw: two, Upper: two, Line: line})
				i += 2
				continue
			}
		}

		// Single-char operator
		raw := string(ch)
		tokens = append(tokens, Token{Kind: TokOp, Raw: raw, Upper: raw, Line: line})
		i++
	}

	return tokens
}

func matchDollarTag(s string) (tag string, length int, ok bool) {
	if len(s) < 2 || s[0] != '$' {
		return "", 0, false
	}
	if s[1] == '$' {
		return "$$", 2, true
	}
	if !isIdentStart(s[1]) {
		return "", 0, false
	}
	j := 2
	for j < len(s) && (isIdentStart(s[j]) || isASCIIDigit(s[j])) {
		j++
	}
	if j < len(s) && s[j] == '$' {
		return s[:j+1], j + 1, true
	}
	return "", 0, false
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' || b >= 0x80
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || isASCIIDigit(b) || b == '$'
}

// ParsePGDuration parses PostgreSQL timeout parameter values such as
// '2s', '500ms', '1min', '100 us', '0', or bare integer milliseconds (e.g. 2000).
// Returns (duration, true) on success, or (0, false) if unparseable.
func ParsePGDuration(raw string) (time.Duration, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	if strings.EqualFold(s, "default") {
		return 0, true
	}

	// Split leading numeric part from optional unit suffix.
	idx := 0
	for idx < len(s) && (unicode.IsDigit(rune(s[idx])) || s[idx] == '.') {
		idx++
	}
	if idx == 0 {
		return 0, false
	}
	numStr := s[:idx]
	unit := strings.ToLower(strings.TrimSpace(s[idx:]))

	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil || val < 0 {
		return 0, false
	}

	var mult time.Duration
	switch unit {
	case "", "ms":
		// PostgreSQL default unit for lock_timeout / statement_timeout is milliseconds.
		mult = time.Millisecond
	case "us":
		mult = time.Microsecond
	case "s":
		mult = time.Second
	case "min":
		mult = time.Minute
	case "h":
		mult = time.Hour
	case "d":
		mult = 24 * time.Hour
	default:
		return 0, false
	}

	return time.Duration(val * float64(mult)), true
}
