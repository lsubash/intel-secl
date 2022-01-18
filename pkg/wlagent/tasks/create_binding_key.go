/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	cLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/tpmprovider"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/common"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"github.com/pkg/errors"
)

type BindingKey struct {
	Config      *config.Configuration
	T           tpmprovider.TpmFactory
	envPrefix   string
	commandName string
}

var (
	log                  = cLog.GetDefaultLogger()
	secLog               = cLog.GetSecurityLogger()
	bindingKeyHelpPrompt = "No environment variables are required for " + constants.CreateBindingKey + " setup task."
	bindingKeyEnvHelp    = map[string]string{}
)

func (bk BindingKey) Run() error {
	log.Trace("setup/create_binding_key:Run() Entering")
	defer log.Trace("setup/create_binding_key:Run() Leaving")
	fmt.Println("Running setup task: BindingKey")

	log.Info("setup/create_binding_key:Run() Creating binding key.")

	err := common.GenerateKey(bk.Config, tpmprovider.Binding, bk.T, constants.ConfigDirPath)
	if err != nil {
		return errors.Wrap(err, "setup/create_binding_key:Run() Error while generating tpm certified binding key")
	}
	return nil
}

func (bk BindingKey) Validate() error {
	log.Trace("setup/create_binding_key:Validate() Entering")
	defer log.Trace("setup/create_binding_key:Validate() Leaving")

	log.Info("setup/create_binding_key:Validate() Validation for binding key.")

	err := common.ValidateKey(tpmprovider.Binding, constants.ConfigDirPath)
	if err != nil {
		return errors.Wrap(err, "setup/create_binding_key:Validate() Error while validating binding key")
	}

	return nil
}

func (bk BindingKey) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, bindingKeyHelpPrompt, "", bindingKeyEnvHelp)
	fmt.Fprintln(w, "")
}

func (bk BindingKey) SetName(n, e string) {
	bk.commandName = n
	bk.envPrefix = setup.PrefixUnderscroll(e)
}
