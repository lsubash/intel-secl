/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package main

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v5/upgrades/wls/db/src/wls/config"
	"github.com/intel-secl/intel-secl/v5/upgrades/wls/db/src/wls/database"
	"os"

	// Import driver for GORM
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	//Configuration file path
	ConfigFilePath = "/etc/wls/"
)

// main method implements migration of old format of WLS Database to new format
func main() {

	fmt.Println("Starting WLS Database Changes")

	fmt.Println("Reading config from : " + ConfigFilePath)
	conf, err := config.LoadConfig(ConfigFilePath)
	if err != nil {
		fmt.Println("Error in getting DB connection details : ", err)
		os.Exit(1)
	}

	//Checking database connection establishment
	dataStore, err := database.GetDatabaseConnection(&conf.DB)
	if err != nil {
		fmt.Println("Error in establishing database connection")
		os.Exit(1)
	}

	err = database.RenameDatabase(dataStore.Db)
	if err != nil {
		fmt.Println("\nDatabase Changes are NOT successful")
	} else {
		fmt.Println("\nDatabase Changes are successful")
		os.Exit(1)
	}
}
