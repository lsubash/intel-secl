/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"time"
)

type ReportStore struct {
	Store *DataStore
}

func NewReportStore(store *DataStore) *ReportStore {
	return &ReportStore{Store: store}
}

//Create creates a new Report
func (r *ReportStore) Create(re *model.Report) (*model.Report, error) {
	defaultLog.Trace("postgres/report_store:Create() Entering")
	defer defaultLog.Trace("postgres/report_store:Create() Leaving")

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Create() failed to create new UUID")
	}
	re.ID = newUuid
	dbReport := report{
		ID:          re.ID,
		CreatedAt:   time.Now(),
		InstanceID:  re.InstanceTrustReport.Manifest.InstanceInfo.InstanceID,
		TrustReport: PGTrustReport(re.InstanceTrustReport),
		SignedData:  PGReportSignedData(re.SignedData),
	}
	if err := r.Store.Db.Create(&dbReport).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Create() failed to create WLSReport")
	}
	return re, nil
}

// Retrieve method fetches report for a given Id
func (r *ReportStore) Retrieve(reportId uuid.UUID) (*model.Report, error) {
	defaultLog.Trace("postgres/report_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/report_store:Retrieve() Leaving")

	re := model.Report{}

	row := r.Store.Db.Model(&report{}).Select("id, trust_report, signed_data").Where(&report{ID: reportId}).Row()
	if err := row.Scan(&re.ID, (*PGTrustReport)(&re.InstanceTrustReport), (*PGReportSignedData)(&re.SignedData)); err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Retrieve() failed to scan record")
	}
	return &re, nil
}

// Search method fetches reports for the given filter criteria
func (r *ReportStore) Search(criteria *model.ReportFilter) ([]model.Report, error) {
	defaultLog.Trace("postgres/report_store:Search() Entering")
	defer defaultLog.Trace("postgres/report_store:Search() Leaving")

	var toDate time.Time
	var fromDate time.Time

	if criteria.NumberOfDays != 0 {
		toDate = time.Now().UTC()
		fromDate = toDate.AddDate(0, 0, -(criteria.NumberOfDays)).UTC()
	}

	var tx *gorm.DB
	tx = buildReportSearchQuery(r.Store.Db, criteria.InstanceID, criteria.ReportID, criteria.HardwareUUID, criteria.LatestPerVM, fromDate, toDate)
	if tx == nil {
		return nil, errors.New("postgres/report_store:Search() Unexpected Error. Could not build" +
			" a gorm query object in WLSReport Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Search() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("postgres/report_store:Search() Error closing rows")
		}
	}()

	var reports []model.Report
	for rows.Next() {
		result := model.Report{}
		if err := rows.Scan(&result.ID, (*PGTrustReport)(&result.InstanceTrustReport), (*PGReportSignedData)(&result.SignedData)); err != nil {
			return nil, errors.Wrap(err, "postgres/report_store:Search() failed to scan record")
		}
		reports = append(reports, result)
	}

	return reports, nil

}

// Delete method deletes report for a given Id
func (r *ReportStore) Delete(reportId uuid.UUID) error {
	defaultLog.Trace("postgres/report_store:Delete() Entering")
	defer defaultLog.Trace("postgres/report_store:Delete() Leaving")
	// get the deleted record
	re := report{}
	err := r.Store.Db.Where(&report{ID: reportId}).First(&re).Error
	if gorm.IsRecordNotFoundError(err) {
		return errors.Wrap(err, "no rows in result set")
	} else if err != nil {
		return errors.Wrap(err, "Error while retrieving the DB records")
	}

	if err := r.Store.Db.Delete(&report{ID: reportId}).Error; err != nil {
		return errors.Wrap(err, "postgres/report_store:Delete() failed to delete Report")
	}

	return nil
}

// buildReportSearchQuery helper function to build the query object for a Report search
func buildReportSearchQuery(tx *gorm.DB, instanceID, reportID, hardwareUUID uuid.UUID, latestPerVM bool, fromDate, toDate time.Time) *gorm.DB {
	defaultLog.Trace("postgres/report_store:buildReportSearchQuery() Entering")
	defer defaultLog.Trace("postgres/report_store:buildReportSearchQuery() Leaving")
	if tx == nil {
		return nil
	}
	tx = tx.Model(&report{}).Select("id, trust_report, signed_data")

	if reportID != uuid.Nil {
		tx = tx.Where("id = ?", reportID.String())
	}

	if instanceID != uuid.Nil {
		tx = tx.Where("trust_report -> 'instance_manifest' -> 'instance_info' ->> 'instance_id' = ? ", instanceID.String())
	}

	if hardwareUUID != uuid.Nil {
		tx = tx.Where("trust_report -> 'instance_manifest' -> 'instance_info' ->> 'host_hardware_uuid' = ?", hardwareUUID.String())
	}

	if !fromDate.IsZero() {
		tx = tx.Where("CAST(created AS TIMESTAMP) >= CAST(? AS TIMESTAMP)", fromDate)
	}

	if !toDate.IsZero() {
		tx = tx.Where("CAST(created AS TIMESTAMP) < CAST(? AS TIMESTAMP)", toDate)
	}

	if latestPerVM {
		tx = tx.Order("created desc").First(&report{})
	}
	return tx
}
