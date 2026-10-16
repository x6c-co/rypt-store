package secrets

import (
	"errors"
	"sort"
	"strings"
)

// Entry is one parsed KEY=value assignment.
type Entry struct {
	Name  string
	Value string
	Line  int
}

// Rejection is a line the parser could not accept.
type Rejection struct {
	Name   string
	Line   int
	Reason string
}

// ParseDotenv parses a .env file with the common dotenv rules (feature 01
// 3.7): KEY=value, an optional "export " prefix, single and double quotes,
// \n and other escapes inside double quotes, multi-line values inside
// quotes, # comments on their own line or after a value, and blank lines.
// Invalid names are rejected with their line number. When a name repeats,
// the last assignment wins.
func ParseDotenv(src string) ([]Entry, []Rejection) {
	src = strings.TrimPrefix(strings.ReplaceAll(src, "\r\n", "\n"), "\ufeff")
	p := &dotenvParser{src: src, line: 1}
	var entries []Entry
	var rejected []Rejection
	index := map[string]int{}
	for {
		p.skipBlank()
		if p.pos >= len(p.src) {
			break
		}
		lineNo := p.line
		name, value, err := p.assignment()
		if err != nil {
			rejected = append(rejected, Rejection{Name: name, Line: lineNo, Reason: err.Error()})
			p.skipLine()
			continue
		}
		if err := ValidateName(name); err != nil {
			rejected = append(rejected, Rejection{Name: name, Line: lineNo, Reason: err.Error()})
			continue
		}
		if err := ValidateValue(value); err != nil {
			rejected = append(rejected, Rejection{Name: name, Line: lineNo, Reason: err.Error()})
			continue
		}
		e := Entry{Name: name, Value: value, Line: lineNo}
		if j, ok := index[name]; ok {
			entries[j] = e
			continue
		}
		index[name] = len(entries)
		entries = append(entries, e)
	}
	return entries, rejected
}

type dotenvParser struct {
	src  string
	pos  int
	line int
}

func (p *dotenvParser) peek() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

func (p *dotenvParser) advance() byte {
	c := p.src[p.pos]
	p.pos++
	if c == '\n' {
		p.line++
	}
	return c
}

// skipBlank skips whitespace, blank lines and comment lines.
func (p *dotenvParser) skipBlank() {
	for p.pos < len(p.src) {
		switch c := p.peek(); {
		case c == ' ' || c == '\t' || c == '\n':
			p.advance()
		case c == '#':
			p.skipLine()
		default:
			return
		}
	}
}

// skipLine moves past the end of the current line.
func (p *dotenvParser) skipLine() {
	for p.pos < len(p.src) {
		if p.advance() == '\n' {
			return
		}
	}
}

func (p *dotenvParser) skipSpaces() {
	for p.peek() == ' ' || p.peek() == '\t' {
		p.advance()
	}
}

// restOfLine returns the text up to the end of the line without consuming
// the newline.
func (p *dotenvParser) restOfLine() string {
	start := p.pos
	for p.pos < len(p.src) && p.peek() != '\n' {
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *dotenvParser) assignment() (name, value string, err error) {
	if strings.HasPrefix(p.src[p.pos:], "export ") || strings.HasPrefix(p.src[p.pos:], "export\t") {
		p.pos += len("export")
		p.skipSpaces()
	}
	start := p.pos
	for p.pos < len(p.src) && p.peek() != '=' && p.peek() != '\n' {
		p.pos++
	}
	name = strings.TrimSpace(p.src[start:p.pos])
	if p.peek() != '=' {
		// The line may be a stray value; do not echo it back as a name.
		return "", "", errors.New("expected KEY=value")
	}
	p.advance()
	p.skipSpaces()
	switch q := p.peek(); q {
	case '"', '\'':
		p.advance()
		value, err = p.quoted(q)
		if err != nil {
			return name, "", err
		}
		// Only a comment may follow the closing quote.
		if tail := strings.TrimSpace(p.restOfLine()); tail != "" && !strings.HasPrefix(tail, "#") {
			return name, "", errors.New("unexpected text after the closing quote")
		}
	default:
		value = p.restOfLine()
		if c := strings.Index(value, " #"); c >= 0 {
			value = value[:c]
		} else if c := strings.Index(value, "\t#"); c >= 0 {
			value = value[:c]
		}
		value = strings.TrimSpace(value)
	}
	return name, value, nil
}

// quoted reads up to the closing quote q, which may be lines away.
func (p *dotenvParser) quoted(q byte) (string, error) {
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.advance()
		if c == q {
			return b.String(), nil
		}
		if q == '"' && c == '\\' && p.pos < len(p.src) {
			switch e := p.advance(); e {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '"', '\\', '$', '`':
				b.WriteByte(e)
			default:
				b.WriteByte('\\')
				b.WriteByte(e)
			}
			continue
		}
		b.WriteByte(c)
	}
	return "", errors.New("missing closing " + string(q) + " quote")
}

// FormatDotenv writes values as KEY="value" lines in name order, escaping
// so that ParseDotenv reads them back unchanged.
func FormatDotenv(values map[string]string) string {
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", `\$`, "`", "\\`")
	for _, n := range names {
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(esc.Replace(values[n]))
		b.WriteString("\"\n")
	}
	return b.String()
}

// FormatShell writes values as `export KEY='value'` lines for a POSIX shell.
func FormatShell(values map[string]string) string {
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString("export ")
		b.WriteString(n)
		b.WriteString("='")
		b.WriteString(strings.ReplaceAll(values[n], "'", `'\''`))
		b.WriteString("'\n")
	}
	return b.String()
}
