/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"os"
	"path"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	hvsclient "github.com/intel-secl/intel-secl/v5/pkg/wlagent/clients"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/common"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"

	"github.com/pkg/errors"
)

var (
	registerSigningKeyHelpPrompt = "Following environment variables are required for " +
		constants.RegisterSigningKeyCommand + " setup task."
	registerSigningKeyEnvHelp = map[string]string{
		constants.HvsUrlEnv:      "Host Verification Service API endpoint",
		constants.BearerTokenEnv: "Bearer token for accessing AAS api",
	}
)

type RegisterSigningKey struct {
	Config      *config.Configuration
	HvsUrl      string
	envPrefix   string
	commandName string
}

func (rs RegisterSigningKey) Run() error {
	log.Trace("setup/register_signing_key:Run() Entering")
	defer log.Trace("setup/register_signing_key:Run() Leaving")
	fmt.Println("Running setup task: RegisterSigningKey")

	log.Info("setup/register_signing_key:Run() Registering signing key with host verification service.")
	signingKey, err := config.GetSigningKeyFromFile()
	if err != nil {
		return errors.Wrap(err, "setup/register_signing_key:Run() error reading signing key from  file")
	}

	httpRequestBody, err := common.CreateRequest(rs.Config.TrustAgent.AikPemFile, signingKey)
	if err != nil {
		return errors.Wrap(err, "setup/register_signing_key:Run() error registering signing key")
	}

	registerKey, err := hvsclient.CertifyHostSigningKey(rs.Config.Hvs.APIUrl, httpRequestBody)
	if err != nil {
		secLog.WithError(err).Error("setup/register_signing_key:Run() error while certify host signing key from hvs")
		return errors.Wrap(err, "setup/register_signing_key:Run() error while certify host signing key from hvs")
	}

	err = common.WriteKeyCertToDisk(path.Join(constants.ConfigDirPath, constants.SigningKeyPemFileName), registerKey.SigningKeyCertificate)
	if err != nil {
		return errors.New("setup/register_signing_key:Run() error writing signing key certificate to file")
	}
	return nil
}

// Validate checks whether the Register Signing Key task was completed successfully
func (rs RegisterSigningKey) Validate() error {
	log.Trace("setup/register_signing_key:Validate() Entering")
	defer log.Trace("setup/register_signing_key:Validate() Leaving")

	log.Info("setup/register_signing_key:Validate() Validation for registering signing key.")
	signingKeyCertPath := path.Join(constants.ConfigDirPath, constants.SigningKeyPemFileName)
	_, err := os.Stat(signingKeyCertPath)
	if os.IsNotExist(err) {
		return errors.New("setup/register_signing_key:Validate() Signing key certificate file does not exist")
	}
	return nil
}

func (rs RegisterSigningKey) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, registerSigningKeyHelpPrompt, "", registerSigningKeyEnvHelp)
	fmt.Fprintln(w, "")
}

func (rs RegisterSigningKey) SetName(n, e string) {
	rs.commandName = n
	rs.envPrefix = setup.PrefixUnderscroll(e)
}
