/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	cLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/pkg/errors"
)

var log = cLog.GetDefaultLogger()

func UnwrapKey(wrappedKey []byte, privateKeyLocation string) ([]byte, error) {
	log.Trace("pkg/wpm/util/encrypt.go:UnwrapKey() Entering")
	defer log.Trace("pkg/wpm/util/encrypt.go:UnwrapKey() Leaving")

	privateKey, err := ioutil.ReadFile(privateKeyLocation)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading private envelope key file")
	}

	privateKeyBlock, _ := pem.Decode(privateKey)
	var pri *rsa.PrivateKey
	pri, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding private envelope key")
	}

	decryptedKey, err := rsa.DecryptOAEP(sha512.New384(), rand.Reader, pri, wrappedKey, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error while decrypting the key")
	}

	log.Info("pkg/wpm/util/encrypt.go:Encrypt() Successfully unwrapped key")
	return decryptedKey, nil
}
