// Copyright The Helm Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helmstrvals

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrNotList indicates that a non-list was treated as a list.
var ErrNotList = errors.New("not a list")

// MaxIndex is the maximum index that will be allowed by setIndex.
var MaxIndex = 65536

// MaxNestedNameLevel is the maximum level of nesting for a value name.
var MaxNestedNameLevel = 30

// ParseInto parses a strvals line and merges the result into dest.
//
// If the strvals string has a key that exists in dest, it overwrites the
// dest version.
func ParseInto(s string, dest map[string]interface{}) error {
	scanner := bytes.NewBufferString(s)
	t := newParser(scanner, dest, false)
	return t.parse()
}

// ParseIntoString parses a strvals line and merges the result into dest,
// always returning a string as the value.
func ParseIntoString(s string, dest map[string]interface{}) error {
	scanner := bytes.NewBufferString(s)
	t := newParser(scanner, dest, true)
	return t.parse()
}

type parser struct {
	sc         *bytes.Buffer
	data       map[string]interface{}
	stringBool bool
}

func newParser(sc *bytes.Buffer, data map[string]interface{}, stringBool bool) *parser {
	return &parser{sc: sc, data: data, stringBool: stringBool}
}

func (t *parser) parse() error {
	for {
		err := t.key(t.data, 0)
		if err == nil {
			continue
		}
		if err == io.EOF {
			return nil
		}
		return err
	}
}

func runeSet(r []rune) map[rune]bool {
	s := make(map[rune]bool, len(r))
	for _, rr := range r {
		s[rr] = true
	}
	return s
}

func (t *parser) key(data map[string]interface{}, nestedNameLevel int) (reterr error) {
	defer func() {
		if r := recover(); r != nil {
			reterr = fmt.Errorf("unable to parse key: %s", r)
		}
	}()
	stop := runeSet([]rune{'=', '[', ',', '.'})
	for {
		switch k, last, err := runesUntil(t.sc, stop); {
		case err != nil:
			if len(k) == 0 {
				return err
			}
			return fmt.Errorf("key %q has no value", string(k))
		case last == '[':
			i, err := t.keyIndex()
			if err != nil {
				return fmt.Errorf("error parsing index: %w", err)
			}
			kk := string(k)
			list := []interface{}{}
			if _, ok := data[kk]; ok {
				list = data[kk].([]interface{})
			}
			list, err = t.listItem(list, i, nestedNameLevel)
			set(data, kk, list)
			return err
		case last == '=':
			vl, e := t.valList()
			switch e {
			case nil:
				set(data, string(k), vl)
				return nil
			case io.EOF:
				set(data, string(k), "")
				return e
			case ErrNotList:
				rs, e := t.val()
				if e != nil && e != io.EOF {
					return e
				}
				set(data, string(k), typedVal(rs, t.stringBool))
				return e
			default:
				return e
			}
		case last == ',':
			set(data, string(k), "")
			return fmt.Errorf("key %q has no value (cannot end with ,)", string(k))
		case last == '.':
			nestedNameLevel++
			if nestedNameLevel > MaxNestedNameLevel {
				return fmt.Errorf("value name nested level is greater than maximum supported nested level of %d", MaxNestedNameLevel)
			}

			inner := map[string]interface{}{}
			if _, ok := data[string(k)]; ok {
				inner = data[string(k)].(map[string]interface{})
			}

			e := t.key(inner, nestedNameLevel)
			if e == nil && len(inner) == 0 {
				return fmt.Errorf("key map %q has no value", string(k))
			}
			if len(inner) != 0 {
				set(data, string(k), inner)
			}
			return e
		}
	}
}

func set(data map[string]interface{}, key string, val interface{}) {
	if len(key) == 0 {
		return
	}
	data[key] = val
}

func setIndex(list []interface{}, index int, val interface{}) (l2 []interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("error processing index %d: %s", index, r)
		}
	}()

	if index < 0 {
		return list, fmt.Errorf("negative %d index not allowed", index)
	}
	if index > MaxIndex {
		return list, fmt.Errorf("index of %d is greater than maximum supported index of %d", index, MaxIndex)
	}
	if len(list) <= index {
		newlist := make([]interface{}, index+1)
		copy(newlist, list)
		list = newlist
	}
	list[index] = val
	return list, nil
}

func (t *parser) keyIndex() (int, error) {
	stop := runeSet([]rune{']'})
	v, _, err := runesUntil(t.sc, stop)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(v))
}

func (t *parser) listItem(list []interface{}, i, nestedNameLevel int) ([]interface{}, error) {
	if i < 0 {
		return list, fmt.Errorf("negative %d index not allowed", i)
	}
	stop := runeSet([]rune{'[', '.', '='})
	switch k, last, err := runesUntil(t.sc, stop); {
	case len(k) > 0:
		return list, fmt.Errorf("unexpected data at end of array index: %q", k)
	case err != nil:
		return list, err
	case last == '=':
		vl, e := t.valList()
		switch e {
		case nil:
			return setIndex(list, i, vl)
		case io.EOF:
			return setIndex(list, i, "")
		case ErrNotList:
			rs, e := t.val()
			if e != nil && e != io.EOF {
				return list, e
			}
			return setIndex(list, i, typedVal(rs, t.stringBool))
		default:
			return list, e
		}
	case last == '[':
		nextI, err := t.keyIndex()
		if err != nil {
			return list, fmt.Errorf("error parsing index: %w", err)
		}
		var crtList []interface{}
		if len(list) > i {
			existed := list[i]
			if existed != nil {
				crtList = list[i].([]interface{})
			}
		}
		list2, err := t.listItem(crtList, nextI, nestedNameLevel)
		if err != nil {
			return list, err
		}
		return setIndex(list, i, list2)
	case last == '.':
		inner := map[string]interface{}{}
		if len(list) > i {
			var ok bool
			inner, ok = list[i].(map[string]interface{})
			if !ok {
				list[i] = map[string]interface{}{}
				inner = list[i].(map[string]interface{})
			}
		}

		e := t.key(inner, nestedNameLevel)
		if e != nil {
			return list, e
		}
		return setIndex(list, i, inner)
	default:
		return nil, fmt.Errorf("parse error: unexpected token %v", last)
	}
}

func (t *parser) val() ([]rune, error) {
	stop := runeSet([]rune{','})
	v, _, err := runesUntil(t.sc, stop)
	return v, err
}

func (t *parser) valList() ([]interface{}, error) {
	r, _, e := t.sc.ReadRune()
	if e != nil {
		return []interface{}{}, e
	}

	if r != '{' {
		t.sc.UnreadRune()
		return []interface{}{}, ErrNotList
	}

	list := []interface{}{}
	stop := runeSet([]rune{',', '}'})
	for {
		switch rs, last, err := runesUntil(t.sc, stop); {
		case err != nil:
			if err == io.EOF {
				err = errors.New("list must terminate with '}'")
			}
			return list, err
		case last == '}':
			if r, _, e := t.sc.ReadRune(); e == nil && r != ',' {
				t.sc.UnreadRune()
			}
			list = append(list, typedVal(rs, t.stringBool))
			return list, nil
		case last == ',':
			list = append(list, typedVal(rs, t.stringBool))
		}
	}
}

func runesUntil(in io.RuneReader, stop map[rune]bool) ([]rune, rune, error) {
	v := []rune{}
	for {
		switch r, _, e := in.ReadRune(); {
		case e != nil:
			return v, r, e
		case stop[r]:
			return v, r, nil
		case r == '\\':
			next, _, e := in.ReadRune()
			if e != nil {
				return v, next, e
			}
			v = append(v, next)
		default:
			v = append(v, r)
		}
	}
}

func typedVal(v []rune, st bool) interface{} {
	val := string(v)

	if st {
		return val
	}

	if strings.EqualFold(val, "true") {
		return true
	}

	if strings.EqualFold(val, "false") {
		return false
	}

	if strings.EqualFold(val, "null") {
		return nil
	}

	if strings.EqualFold(val, "0") {
		return int64(0)
	}

	if len(val) != 0 && val[0] != '0' {
		if iv, err := strconv.ParseInt(val, 10, 64); err == nil {
			return iv
		}
	}

	return val
}
