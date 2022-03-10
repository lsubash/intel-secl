/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"encoding/xml"
	"time"
)

// Saml is used to represent saml report struct
type Saml struct {
	XMLName   xml.Name    `xml:"Assertion"`
	Subject   Subject     `xml:"Subject>SubjectConfirmation>SubjectConfirmationData"`
	Attribute []Attribute `xml:"AttributeStatement>Attribute"`
	Signature string      `xml:"Signature>KeyInfo>X509Data>X509Certificate"`
}

type Subject struct {
	XMLName      xml.Name  `xml:"SubjectConfirmationData"`
	NotBefore    time.Time `xml:"NotBefore,attr"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
}

type Attribute struct {
	XMLName        xml.Name `xml:"Attribute"`
	Name           string   `xml:"Name,attr"`
	AttributeValue string   `xml:"AttributeValue"`
}
