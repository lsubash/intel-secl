/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

/**
** @author srege
**/

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"strconv"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	hvsclient "github.com/intel-secl/intel-secl/v5/pkg/wlagent/clients"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/common"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"

	"github.com/pkg/errors"
)

const registerBindingKeyHelpPrompt = "Following environment variables are required for " +
	constants.RegisterBindingKeyCommand + " setup task."

var registerBindingKeyEnvHelp = map[string]string{
	constants.HvsUrlEnv:      "Host Verification Service API endpoint",
	constants.BearerTokenEnv: "Bearer token for accessing AAS api",
	constants.TAUserNameEnv:  "TrustAgent component service account for changing binding key file ownership",
}

type RegisterBindingKey struct {
	Config      *config.Configuration
	HvsUrl      string
	TaUserName  string
	envPrefix   string
	commandName string
}

func (rb RegisterBindingKey) Run() error {
	log.Trace("setup/register_binding_key:Run() Entering")
	defer log.Trace("setup/register_binding_key:Run() Leaving")
	fmt.Println("Running setup task: RegisterBindingKey")

	log.Info("setup/register_binding_key:Run() Registering binding key with host verification service.")
	bindingKey, err := config.GetBindingKeyFromFile()
	if err != nil {
		return errors.Wrap(err, "setup/register_binding_key:Run() error reading binding key from  file.")
	}

	httpRequestBody, err := common.CreateRequest(rb.Config.TrustAgent.AikPemFile, bindingKey)
	if err != nil {
		return errors.Wrap(err, "setup/register_binding_key:Run() error registering binding key.")
	}

	registerKey, err := hvsclient.CertifyHostBindingKey(rb.Config.Hvs.APIUrl, httpRequestBody)
	if err != nil {
		secLog.WithError(err).Error("setup/register_binding_key:Run() error while certifying host binding key with hvs")
		return errors.Wrap(err, "setup/register_binding_key:Run() error while certifying host binding key with hvs")
	}

	err = common.WriteKeyCertToDisk(constants.ConfigDirPath+constants.BindingKeyPemFileName, registerKey.BindingKeyCertificate)
	if err != nil {
		return errors.New("setup/register_binding_key:Run() error writing binding key certificate to file")
	}

	// tagent container is run as root user, skip setting permission for tagent user in case of containerized deployment
	if _, err := os.Stat("/.container-env"); err == nil {
		return nil
	}
	return rb.setBindingKeyPemFileOwner()
}

// Validate checks whether the register binding key task was completed successfully
func (rb RegisterBindingKey) Validate() error {
	log.Trace("setup/register_binding_key:Validate() Entering")
	defer log.Trace("setup/register_binding_key:Validate() Leaving")

	log.Info("setup/register_binding_key:Validate() Validation for registering binding key.")
	bindingKeyCertFilePath := path.Join(constants.ConfigDirPath, constants.BindingKeyPemFileName)
	_, err := os.Stat(bindingKeyCertFilePath)
	if os.IsNotExist(err) {
		return errors.New("setup/register_binding_key:Validate() binding key certificate file does not exist")
	}
	return nil
}

// setBindingKeyFileOwner sets the owner of the binding key file to the trustagent user
// This is necessary for the TrustAgent to add the binding key to the manifest.
func (rb RegisterBindingKey) setBindingKeyPemFileOwner() (err error) {
	log.Trace("setup/register_binding_key:setBindingKeyPemFileOwner() Entering")
	defer log.Trace("setup/register_binding_key:setBindingKeyPemFileOwner() Leaving")
	var usr *user.User
	err = nil
	// get the user id from the configuration variable that we have set
	if rb.Config.TrustAgent.User == "" {
		return errors.New("setup/register_binding_key:setBindingKeyPemFileOwner() trust agent user name cannot be empty in configuration")
	}

	if usr, err = user.Lookup(rb.Config.TrustAgent.User); err != nil {
		return errors.Wrapf(err, "setup/register_binding_key:setBindingKeyPemFileOwner() could not lookup up user id of trust agent user : %s", rb.Config.TrustAgent.User)
	}

	uid, _ := strconv.Atoi(usr.Uid)
	gid, _ := strconv.Atoi(usr.Gid)
	// no need to check errors for the above two call since had just looked up the user
	// using the user.Lookup call
	err = os.Chown(constants.ConfigDirPath+constants.BindingKeyPemFileName, uid, gid)
	if err != nil {
		return errors.Wrapf(err, "setup/register_binding_key:setBindingKeyPemFileOwner() Could not set permission for File %s", constants.ConfigDirPath+constants.BindingKeyPemFileName)
	}

	return nil
}

func (rb RegisterBindingKey) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, registerBindingKeyHelpPrompt, "", registerBindingKeyEnvHelp)
	fmt.Fprintln(w, "")
}

func (rb RegisterBindingKey) SetName(n, e string) {
	rb.commandName = n
	rb.envPrefix = setup.PrefixUnderscroll(e)
}
