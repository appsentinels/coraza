// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/appsentinels/coraza/v3/experimental/plugins/plugintypes"
)

type xmlBodyProcessor struct {
}

/*
[[ AppSentinels -- commented for better XML param addressing
func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	values, contents, err := readXML(reader)
	if err != nil {
		return err
	}
	col := v.RequestXML()
	col.Set("//@*", values)
	col.Set("/*", contents)
	return nil
}
]]
*/

// [[ AppSentinels -- modified to include all the params into collection as per datapath addressing ]]
func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	data, err := readXML(reader)
	if err != nil {
		return err
	}
	col := v.ArgsPost()
	for key, value := range data {
		col.SetIndex(key, 0, value)
	}
	return nil
}

// ]]

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

/*
[[ AppSentinels -- commented for better XML param addressing
func readXML(reader io.Reader) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		if token == nil {
			break
		}
		switch tok := token.(type) {
		case xml.StartElement:
			for _, attr := range tok.Attr {
				attrs = append(attrs, attr.Value)
			}
		case xml.CharData:
			if c := strings.TrimSpace(string(tok)); c != "" {
				content = append(content, c)
			}
		}
	}
	return attrs, content, nil
}
]] */

func readXML(reader io.Reader) (map[string]string, error) {
	res := make(map[string]string)
	dec := xml.NewDecoder(reader)
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	// Track namespace prefixes
	nsMap := make(map[string]string)  // URI -> prefix
	defaultNS := make(map[int]string) // depth -> default namespace
	depth := 0

	var path []string
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF {
			return nil, err
		}
		if token == nil {
			break
		}

		switch tok := token.(type) {
		case xml.StartElement:
			depth++
			// Update namespace mappings
			for _, attr := range tok.Attr {
				if attr.Name.Space == "xmlns" {
					nsMap[attr.Value] = attr.Name.Local
				} else if attr.Name.Space == "" && attr.Name.Local == "xmlns" {
					defaultNS[depth] = attr.Value
				}
			}

			// Handle namespaces in element names
			elementName := tok.Name.Local
			if tok.Name.Space != "" {
				// Check if this is a default namespace
				isDefault := false
				for d := depth; d > 0; d-- {
					if ns, ok := defaultNS[d]; ok && ns == tok.Name.Space {
						isDefault = true
						break
					}
				}
				if !isDefault {
					if prefix, ok := nsMap[tok.Name.Space]; ok {
						elementName = prefix + ":" + elementName
					}
				}
			}
			path = append(path, elementName)
			currentPath := "xml." + strings.Join(path, ".")

			// Handle attributes with their namespaces
			for _, attr := range tok.Attr {
				if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
					continue // Skip namespace declarations in the result
				}
				attrName := attr.Name.Local
				if attr.Name.Space != "" {
					if prefix, ok := nsMap[attr.Name.Space]; ok {
						attrName = prefix + ":" + attrName
					}
				}
				attrPath := currentPath + "." + attrName
				res[attrPath] = attr.Value
			}

		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
			delete(defaultNS, depth)
			depth--

		case xml.CharData:
			if content := strings.TrimSpace(string(tok)); content != "" {
				currentPath := "xml." + strings.Join(path, ".")
				res[currentPath] = content
			}
		}
	}
	return res, nil
}

var (
	_ plugintypes.BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("xml", func() plugintypes.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
