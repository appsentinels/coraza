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

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	data, err := readXML(reader)
	if err != nil {
		return err
	}
	col := v.ResponseArgs()
	for key, value := range data {
		col.SetIndex(key, 0, value)
	}
	return nil
}

func readXML(reader io.Reader) (map[string]string, error) {
	res := make(map[string]string)
	dec := xml.NewDecoder(reader)
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	// Track namespace prefixes
	nsMap := make(map[string]string) // URI -> prefix

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
			// Update namespace mappings
			for _, attr := range tok.Attr {
				if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
					prefix := attr.Name.Local
					if attr.Name.Space == "" {
						prefix = "xmlns"
					}
					nsMap[attr.Value] = prefix
				}
			}

			// Handle namespaces in element names
			elementName := tok.Name.Local
			if tok.Name.Space != "" {
				if prefix, ok := nsMap[tok.Name.Space]; ok && prefix != "xmlns" {
					elementName = prefix + ":" + elementName
				} else {
					// If we don't have a mapping, use a default prefix
					elementName = "ns:" + elementName
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
					} else {
						attrName = "ns:" + attrName
					}
				}
				attrPath := currentPath + "." + attrName
				res[attrPath] = attr.Value
			}

		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}

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
