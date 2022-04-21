/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"github.com/intel-secl/intel-secl/v5/pkg/cms/config"
	"github.com/intel-secl/intel-secl/v5/pkg/cms/constants"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

type App struct {
	Config *config.Configuration
}

func TestUpdateServiceConfigRunAndValidate(t *testing.T) {
	log.Trace("tasks/update_service_config:TestUpdateServiceConfigRunAndValidate() Entering")
	defer log.Trace("tasks/update_service_config:TestUpdateServiceConfigRunAndValidate() Leaving")

	a := App{}
	c := config.Configuration{}
	a.Config = &c
	ca := UpdateServiceConfig{
		ConsoleWriter: os.Stdout,
		ServerConfig: commConfig.ServerConfig{
			Port:              65536,
			ReadTimeout:       3,
			ReadHeaderTimeout: 3,
			WriteTimeout:      3,
			IdleTimeout:       3,
			MaxHeaderBytes:    1000,
		},
		DefaultPort: constants.DefaultPort,
		AASApiUrl:   "AAS-url",
		AppConfig:   &a.Config,
	}

	err := ca.Run()
	assert.NoError(t, err)
	errValidation := ca.Validate()
	assert.NoError(t, errValidation)
	ca.PrintHelp(bytes.NewBufferString("test"))
	ca.SetName("test", "test")
}

func TestInvalidPort(t *testing.T) {
	log.Trace("tasks/update_cervice_config_test:TestInvalidPort() Entering")
	defer log.Trace("tasks/update_cervice_config_test:TestInvalidPort() Leaving")

	a := App{}
	c := config.Configuration{}
	ServerConfig := commConfig.ServerConfig{
		Port: 655399,
	}
	c.Server = ServerConfig
	a.Config = &c
	ca := UpdateServiceConfig{
		AppConfig: &a.Config,
	}
	err := ca.Validate()
	assert.Error(t, err)
}
