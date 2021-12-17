/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package database

import (
	"fmt"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	wlsconfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

var Db *postgres.DataStore

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func RenameDatabase(db *gorm.DB) error {
	fmt.Println("Deleting Table Images")
	err := db.Exec("DROP TABLE if exists images cascade").Error
	if err != nil {
		fmt.Printf("Error while Dropping table %v", err)
		return err
	}
	err = db.Exec("ALTER TABLE flavors RENAME TO flavor").Error
	if err != nil {
		fmt.Printf("Error while RENAMING table %v", err)
		return err
	}
	err = db.Exec("ALTER TABLE reports RENAME TO report").Error
	if err != nil {
		fmt.Printf("Error while RENAMING table %v", err)
		return err
	}
	err = db.Exec("ALTER TABLE image_flavors RENAME TO image_flavor").Error
	if err != nil {
		fmt.Printf("Error while RENAMING table %v", err)
		return err
	}
	return nil
}

func InitDatabase(cfg *commConfig.DBConfig) (*postgres.DataStore, error) {

	// Create conf for DBTypePostgres
	conf := postgres.Config{
		Vendor:            constants.DBTypePostgres,
		Host:              cfg.Host,
		Port:              cfg.Port,
		User:              cfg.Username,
		Password:          cfg.Password,
		Dbname:            cfg.DBName,
		SslMode:           cfg.SSLMode,
		SslCert:           cfg.SSLCert,
		ConnRetryAttempts: cfg.ConnectionRetryAttempts,
		ConnRetryTime:     cfg.ConnectionRetryTime,
	}

	// Creates a DBTypePostgres DB instance
	dataStore, err := postgres.NewDataStore(&conf)
	if err != nil {
		return nil, errors.Wrap(err, "Error instantiating Database")
	}

	return dataStore, nil
}

//GetDatabaseConnection returns a postgres.DataStore instance if establishing connection to Postgres DB is successful
func GetDatabaseConnection(cfg *wlsconfig.DBConfig) (*postgres.DataStore, error) {
	db, dbErr := InitDatabase(cfg)
	if dbErr != nil {
		fmt.Println("Error in establishing connection to Db")
		return nil, dbErr
	}
	return db, nil
}
