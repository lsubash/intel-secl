/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"github.com/intel-secl/intel-secl/v5/pkg/cms/config"
	"github.com/intel-secl/intel-secl/v5/pkg/cms/constants"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestAuthTokenRunAndValidate(t *testing.T) {
	log.Trace("tasks/authtoken_test:TestAuthTokenRun() Entering")
	defer log.Trace("tasks/authtoken_test:TestAuthTokenRun() Leaving")
	path, _ := CreateTestFilePath()
	c := config.Configuration{}

	ca := CmsAuthToken{
		ConsoleWriter:             os.Stdout,
		AasTlsCn:                  c.AasTlsCn,
		AasJwtCn:                  c.AasJwtCn,
		AasTlsSan:                 c.AasTlsSan,
		TokenDuration:             c.TokenDurationMins,
		TrustedJWTSigningCertsDir: path,
		TokenKeyFile:              constants.TokenKeyFile,
	}

	err := ca.Run()
	assert.NoError(t, err)
	errValidate := ca.Validate()
	assert.NoError(t, errValidate)
	os.Remove(path + constants.TokenKeyFile)
	errValidationJwt := ca.Validate()
	assert.Error(t, errValidationJwt)
	ca.PrintHelp(bytes.NewBufferString("test"))
	ca.SetName("test", "test")
	DeleteTestFilePath(path)
}
