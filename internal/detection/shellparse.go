/*
Hiten | 2026
shellparse.go

Small shell tokenizer for commands typed into the fake SSH shell.

It splits a line into simple commands on ; && || | & and newlines,
then splits each simple command into words while honouring single
quotes, double quotes and backslash escapes. It does not expand
variables, globs or substitutions. That is enough for rules that
need the command name and its arguments, and it stops matches on
text that only mentions a command, such as `echo curl`.
*/

package detection

import (
	"path"
	"strings"
)

// SimpleCommand is one command from a line, after wrappers such
// as sudo and leading VAR=value assignments are removed.
type SimpleCommand struct {
	Name string
	Args []string
	Raw  string
}

// wrappers run the next word as the real command.
var wrappers = map[string]bool{
	"sudo": true, "nohup": true, "busybox": true, "env": true,
	"time": true, "exec": true, "command": true, "nice": true,
}

// options of sudo and nice that consume the following word
var optionWithArg = map[string]bool{
	"-u": true, "-g": true, "-U": true, "-C": true, "-p": true,
}

// ParseCommandLine returns the simple commands in line.
func ParseCommandLine(line string) []SimpleCommand {
	var cmds []SimpleCommand
	for _, seg := range splitSegments(line) {
		words := splitWords(seg)
		for len(words) > 0 && isAssignment(words[0]) {
			words = words[1:]
		}
		for len(words) > 0 && wrappers[path.Base(words[0])] {
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				takesArg := optionWithArg[words[0]]
				words = words[1:]
				if takesArg && len(words) > 0 {
					words = words[1:]
				}
			}
			for len(words) > 0 && isAssignment(words[0]) {
				words = words[1:]
			}
		}
		if len(words) == 0 {
			continue
		}
		cmds = append(cmds, SimpleCommand{
			Name: path.Base(words[0]),
			Args: words[1:],
			Raw:  strings.TrimSpace(seg),
		})
	}
	return cmds
}

func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i, c := range w[:eq] {
		ok := c == '_' || (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// splitSegments splits on command separators outside quotes.
func splitSegments(line string) []string {
	var (
		segs   []string
		cur    strings.Builder
		single bool
		double bool
	)
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			segs = append(segs, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && !single && i+1 < len(line):
			cur.WriteByte(c)
			cur.WriteByte(line[i+1])
			i++
		case c == '\'' && !double:
			single = !single
			cur.WriteByte(c)
		case c == '"' && !single:
			double = !double
			cur.WriteByte(c)
		case !single && !double && (c == ';' || c == '|' || c == '&' || c == '\n'):
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return segs
}

// splitWords splits one simple command into words.
func splitWords(seg string) []string {
	var (
		words  []string
		cur    strings.Builder
		inWord bool
		single bool
		double bool
	)
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case single:
			if c == '\'' {
				single = false
			} else {
				cur.WriteByte(c)
			}
		case double:
			switch {
			case c == '"':
				double = false
			case c == '\\' && i+1 < len(seg) && strings.IndexByte(`"\$`+"`", seg[i+1]) >= 0:
				cur.WriteByte(seg[i+1])
				i++
			default:
				cur.WriteByte(c)
			}
		case c == '\'':
			single, inWord = true, true
		case c == '"':
			double, inWord = true, true
		case c == '\\' && i+1 < len(seg):
			cur.WriteByte(seg[i+1])
			i++
			inWord = true
		case c == ' ' || c == '\t' || c == '\r':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '>' || c == '<':
			// Redirections end the word and drop the target, which
			// is a file name rather than an argument.
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
			for i+1 < len(seg) && (seg[i+1] == '>' || seg[i+1] == '&') {
				i++
			}
			for i+1 < len(seg) && seg[i+1] == ' ' {
				i++
			}
			for i+1 < len(seg) && seg[i+1] != ' ' {
				i++
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}
