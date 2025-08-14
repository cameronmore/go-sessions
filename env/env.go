// this package implements a simple .env parser. It does not account for multi-line values or the following special
// characters in the key or value: quotation mark ("), equals sign (=), and newline (\n)
package env

import (
	"errors"
	"os"
)

type tokenType int

const (
	character tokenType = iota
	whitespace
	assignment
	comment
	newline
	eof
)

type token struct {
	Value     rune
	tokenType tokenType
}

func openEnv(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

func lex(envData []byte) ([]token, error) {
	var tokens []token

	for _, bte := range envData {
		char := rune(bte)
		switch char {
		case '\n':
			tokens = append(tokens, token{tokenType: newline})
			break
		case ' ':
			tokens = append(tokens, token{tokenType: whitespace})
			break
		case '=':
			tokens = append(tokens, token{tokenType: assignment})
			break
		case '#':
			tokens = append(tokens, token{tokenType: comment})
			break
		default:
			tokens = append(tokens, token{tokenType: character, Value: char})
			break
		}
	}
	tokens = append(tokens, token{tokenType: eof})
	return tokens, nil
}

func parse(tokens []token) (map[string]string, error) {
	envMap := make(map[string]string)
	var expectingKey = true
	var expectingValue = false
	var encounteredassignment = false
	var incomment = false
	var currentKey string = ""
	var currentValue string = ""

	for _, tok := range tokens {
		switch tok.tokenType {
		case character:
			if incomment {
				break
			}
			if expectingKey {
				currentKey += string(tok.Value)
				break
			}
			if expectingValue {
				currentValue += string(tok.Value)
				break
			}
			if !expectingValue {
				return envMap, errors.New("unexpected character encountered")
			}
			break
		case whitespace:
			if incomment {
				break
			}
			if currentKey != "" && !expectingValue && encounteredassignment {
				return envMap, errors.New("expected key-value but found whitespace")
			}
			// if there is some text in the key and value, i.e. if they are both not "", then
			// this whitespace is trailing off the value and should be ignored.
			// so set the expectingValue to false such that if we encounter a character (without a comment),
			// then that case will error
			if currentKey != "" && currentValue != "" && encounteredassignment {
				expectingValue = false
			}
			if currentKey != "" && currentValue == "" && encounteredassignment {
				return envMap, errors.New("expected value but found whitespace")
			}
			break
		case assignment:
			if incomment {
				break
			}
			if encounteredassignment {
				return envMap, errors.New("encountered unexpected assignment operator")
			}
			if !encounteredassignment && currentKey != "" {
				expectingKey = false
				expectingValue = true
				encounteredassignment = true
				break
			}
			if !encounteredassignment && currentKey == "" {
				return envMap, errors.New("missing key")
			}

			break
		case comment:
			incomment = true
			break
		case newline:
			if currentKey != "" && currentValue != "" {
				envMap[currentKey] = currentValue
				currentKey = ""
				currentValue = ""
				expectingKey = true
				expectingValue = false
				incomment = false
				encounteredassignment = false
			}
			// missing key

			if currentKey == "" && encounteredassignment && currentValue != "" {
				return envMap, errors.New("missing key")
			}

			// missing value
			if currentValue == "" && encounteredassignment && currentKey != "" {
				return envMap, errors.New("missing value")
			}

			currentKey = ""
			currentValue = ""
			expectingKey = true
			expectingValue = false
			incomment = false
			encounteredassignment = false
			break
		case eof:
			if currentKey != "" && currentValue != "" {
				envMap[currentKey] = currentValue
				currentKey = ""
				currentValue = ""
				expectingKey = true
				expectingValue = false
				incomment = false
				encounteredassignment = false
			}

			if currentKey == "" && currentValue != "" {
				return envMap, errors.New("found value but missing key")
			}

			if currentKey != "" && currentValue == "" {
				return envMap, errors.New("found key but missing value")
			}
		}

	}
	return envMap, nil
}

// Processes a .env file from a given filename.
func ProcessEnv(filename string) (map[string]string, error) {
	envMap := make(map[string]string)
	envData, err := openEnv(filename)
	if err != nil {
		return envMap, err
	}
	tokens, err := lex(envData)
	if err != nil {
		return envMap, err
	}
	envMap, err = parse(tokens)
	if err != nil {
		return envMap, err
	}
	return envMap, nil
}
