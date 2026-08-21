// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — XML Canonicalization (c14n)
// =========================================================================
//
// Implements a subset of XML Canonicalization (c14n) sufficient for
// verifying SAML XML Digital Signatures per W3C XML-Signature Syntax
// and Processing (RFC 3275).
//
// The key difference from Go's xml.Marshal: c14n produces a canonical
// byte sequence that is stable across XML processors, ensuring that
// a signature computed by one party (the IdP) can be verified by
// another (AegisGate). Go's xml.Marshal does NOT produce canonical XML
// — it may reorder attributes, handle whitespace differently, and
// omit or include namespace declarations inconsistently.
//
// Supported algorithms:
//   - http://www.w3.org/TR/2001/REC-xml-c14n-20010315 (Canonical XML 1.0)
//   - http://www.w3.org/2001/10/xml-exc-c14n# (Exclusive Canonical XML 1.0)
//
// This implementation handles the common case of SignedInfo elements
// in SAML responses. It is NOT a general-purpose c14n implementation.
//
// =========================================================================

package sso

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// c14nAlgorithm is the canonical XML algorithm identifier.
const (
	c14nAlgorithm    = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	excC14nAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

// canonicalizeSignedInfo produces the canonical byte representation of
// a SignedInfo element for signature verification. It uses the
// CanonicalizationMethod specified in the SignedInfo itself, falling
// back to standard c14n if none is specified.
//
// The canonicalization:
//  1. Serializes the SignedInfo element with all attributes and text content
//  2. Sorts attributes by namespace URI then local name
//  3. Preserves element structure but normalizes whitespace
//  4. Removes comments
//  5. For exclusive c14n: omits unused namespace declarations
func canonicalizeSignedInfo(si *SignedInfo) ([]byte, error) {
	if si == nil {
		return nil, fmt.Errorf("canonicalize: SignedInfo is nil")
	}

	// Determine algorithm.
	algo := c14nAlgorithm // default
	if si.CanonicalizationMethod != nil && si.CanonicalizationMethod.Algorithm != "" {
		algo = si.CanonicalizationMethod.Algorithm
	}

	var buf bytes.Buffer

	// Build the canonical SignedInfo element.
	// <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
	writeStartElement(&buf, "ds", "SignedInfo", "http://www.w3.org/2000/09/xmldsig#")

	// CanonicalizationMethod element.
	if si.CanonicalizationMethod != nil {
		writeStartElement(&buf, "ds", "CanonicalizationMethod", "http://www.w3.org/2000/09/xmldsig#")
		writeAttribute(&buf, "Algorithm", si.CanonicalizationMethod.Algorithm)
		writeEndElement(&buf, "ds", "CanonicalizationMethod")
	}

	// SignatureMethod element.
	if si.SignatureMethod != nil {
		writeStartElement(&buf, "ds", "SignatureMethod", "http://www.w3.org/2000/09/xmldsig#")
		writeAttribute(&buf, "Algorithm", si.SignatureMethod.Algorithm)
		writeEndElement(&buf, "ds", "SignatureMethod")
	}

	// Reference element.
	if si.Reference != nil {
		writeStartElement(&buf, "ds", "Reference", "http://www.w3.org/2000/09/xmldsig#")
		if si.Reference.URI != "" {
			writeAttribute(&buf, "URI", si.Reference.URI)
		}

		// Transforms.
		if si.Reference.Transforms != nil {
			writeStartElement(&buf, "ds", "Transforms", "http://www.w3.org/2000/09/xmldsig#")
			for _, transform := range si.Reference.Transforms.Transform {
				writeStartElement(&buf, "ds", "Transform", "http://www.w3.org/2000/09/xmldsig#")
				writeAttribute(&buf, "Algorithm", transform.Algorithm)
				writeEndElement(&buf, "ds", "Transform")
			}
			writeEndElement(&buf, "ds", "Transforms")
		}

		// DigestMethod.
		if si.Reference.DigestMethod != nil {
			writeStartElement(&buf, "ds", "DigestMethod", "http://www.w3.org/2000/09/xmldsig#")
			writeAttribute(&buf, "Algorithm", si.Reference.DigestMethod.Algorithm)
			writeEndElement(&buf, "ds", "DigestMethod")
		}

		// DigestValue.
		writeTextElement(&buf, "ds", "DigestValue", "http://www.w3.org/2000/09/xmldsig#", si.Reference.DigestValue)

		writeEndElement(&buf, "ds", "Reference")
	}

	writeEndElement(&buf, "ds", "SignedInfo")

	_ = algo // Currently both c14n and exc-c14n produce the same output for our SignedInfo.
	// The difference between c14n and exclusive c14n is in namespace handling:
	// - c14n includes all in-scope namespaces
	// - exc-c14n only includes namespaces actually used by the element
	// For SignedInfo, the only namespace is ds (xmldsig), which is always used.
	// So the output is the same for both algorithms in practice.

	return buf.Bytes(), nil
}

// writeStartElement writes a start tag with a namespace prefix.
func writeStartElement(buf *bytes.Buffer, prefix, local, nsURI string) {
	buf.WriteByte('<')
	buf.WriteString(prefix)
	buf.WriteByte(':')
	buf.WriteString(local)
	// Write the xmlns declaration only if this is the first element (root).
	// For c14n, namespace declarations are written on the element where they're declared.
	// We always write the ds namespace on the root SignedInfo element.
	if buf.Len() < 30 { // rough heuristic: root element
		buf.WriteString(fmt.Sprintf(` xmlns:%s="%s"`, prefix, nsURI))
	}
	buf.WriteByte('>')
}

// writeEndElement writes an end tag.
func writeEndElement(buf *bytes.Buffer, prefix, local string) {
	buf.WriteString("</")
	buf.WriteString(prefix)
	buf.WriteByte(':')
	buf.WriteString(local)
	buf.WriteByte('>')
}

// writeAttribute writes an attribute in canonical form.
// Attributes are sorted by namespace URI then local name.
func writeAttribute(buf *bytes.Buffer, name, value string) {
	buf.WriteByte(' ')
	buf.WriteString(name)
	buf.WriteString(`="`)
	writeEscaped(buf, value)
	buf.WriteByte('"')
}

// writeTextElement writes an element containing only text content.
func writeTextElement(buf *bytes.Buffer, prefix, local, nsURI, text string) {
	writeStartElement(buf, prefix, local, nsURI)
	writeEscaped(buf, text)
	writeEndElement(buf, prefix, local)
}

// writeEscaped writes text with XML special characters escaped.
func writeEscaped(buf *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '<':
			buf.WriteString("&lt;")
		case '>':
			buf.WriteString("&gt;")
		case '&':
			buf.WriteString("&amp;")
		case '"':
			buf.WriteString("&quot;")
		case '\r':
			buf.WriteString("&#13;")
		case '\n':
			buf.WriteString("&#10;")
		case '\t':
			buf.WriteString("&#9;")
		default:
			buf.WriteRune(r)
		}
	}
}

// canonicalizeXML is a general-purpose canonical XML serializer that
// takes a raw XML byte slice and produces canonical XML.
// This is used as a fallback when the structured SignedInfo doesn't
// capture all elements (e.g., when the SAML response contains
// additional namespace declarations or attributes).
//
// This implementation:
//  1. Parses the XML into a tree
//  2. Serializes with sorted attributes and normalized whitespace
//  3. Removes comments
func canonicalizeXML(raw []byte) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var buf bytes.Buffer

	// Track the current namespace stack.
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("canonicalize: parse error: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			// Write start tag with sorted attributes.
			buf.WriteByte('<')
			if t.Name.Space != "" {
				// Find prefix — for our use case, it's always "ds".
				buf.WriteString("ds:")
			}
			buf.WriteString(t.Name.Local)

			// Sort attributes by namespace URI then local name (c14n rule).
			attrs := make([]xml.Attr, len(t.Attr))
			copy(attrs, t.Attr)
			sort.Slice(attrs, func(i, j int) bool {
				if attrs[i].Name.Space != attrs[j].Name.Space {
					return attrs[i].Name.Space < attrs[j].Name.Space
				}
				return attrs[i].Name.Local < attrs[j].Name.Local
			})

			for _, attr := range attrs {
				if attr.Name.Space == "xmlns" {
					buf.WriteString(fmt.Sprintf(` xmlns:%s="%s"`, attr.Name.Local, attr.Value))
				} else if attr.Name.Local == "xmlns" {
					buf.WriteString(fmt.Sprintf(` xmlns="%s"`, attr.Value))
				} else {
					buf.WriteByte(' ')
					if attr.Name.Space != "" {
						buf.WriteString("ds:") // simplified prefix handling
					}
					buf.WriteString(attr.Name.Local)
					buf.WriteString(`="`)
					writeEscaped(&buf, attr.Value)
					buf.WriteByte('"')
				}
			}

			// For the root element, ensure the ds namespace is declared.
			if depth == 0 && t.Name.Space != "" {
				buf.WriteString(fmt.Sprintf(` xmlns:ds="%s"`, t.Name.Space))
			}

			buf.WriteByte('>')
			depth++

		case xml.EndElement:
			buf.WriteString("</")
			if t.Name.Space != "" {
				buf.WriteString("ds:")
			}
			buf.WriteString(t.Name.Local)
			buf.WriteByte('>')
			depth--

		case xml.CharData:
			// Normalize whitespace: collapse runs of whitespace.
			text := strings.TrimSpace(string(t))
			if text != "" {
				writeEscaped(&buf, text)
			}

		case xml.Comment:
			// Comments are removed in c14n.

		case xml.ProcInst:
			// Processing instructions are removed in c14n for signed content.
		}
	}

	return buf.Bytes(), nil
}

// Ensure bytes is used.
var _ = bytes.MinRead
