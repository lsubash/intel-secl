/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/tpmprovider"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/common"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"github.com/pkg/errors"
)

var (
	signingKeyEnvHelpPrompt = "No environment variables are required for " + constants.CreateSigningKey + " setup task."
	signingKeyEnvHelp       = map[string]string{}
)

type SigningKey struct {
	Config      *config.Configuration
	T           tpmprovider.TpmFactory
	envPrefix   string
	commandName string
}

func (sk SigningKey) Run() error {
	log.Trace("setup/create_signing_key:Run() Entering")
	defer log.Trace("setup/create_signing_key:Run() Leaving")
	fmt.Println("Running setup task: SigningKey")

	log.Info("setup/create_signing_key:Run() Creating signing key.")

	err := common.GenerateKey(sk.Config, tpmprovider.Signing, sk.T, constants.ConfigDirPath)
	if err != nil {
		return errors.Wrap(err, "setup/create_signing_key:Run() Error while generating tpm certified signing key")
	}
	return nil
}

func (sk SigningKey) Validate() error {
	log.Trace("setup/create_signing_key:Validate() Entering")
	defer log.Trace("setup/create_signing_key:Validate() Leaving")

	log.Info("setup/create_signing_key:Validate() Validation for signing key.")

	err := common.ValidateKey(tpmprovider.Signing, constants.ConfigDirPath)
	if err != nil {
		return errors.Wrap(err, "setup/create_signing_key:Validate() Error while validating signing key")
	}

	return nil
}

func (sk SigningKey) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, signingKeyEnvHelpPrompt, "", signingKeyEnvHelp)
	fmt.Fprintln(w, "")
}

func (sk SigningKey) SetName(n, e string) {
	sk.commandName = n
	sk.envPrefix = setup.PrefixUnderscroll(e)
}
