/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package os

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChownR(t *testing.T) {
	type args struct {
		path string
		uid  int
		gid  int
	}
	_, err := os.Create("Test.txt")
	assert.NoError(t, err)

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate chownR",
			args: args{
				path: "Test.txt",
				uid:  100,
				gid:  100,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ChownR(tt.args.path, tt.args.uid, tt.args.gid); (err != nil) != tt.wantErr {
				t.Errorf("ChownR() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	os.Remove("Test.txt")
}

func TestCopy(t *testing.T) {
	type args struct {
		src string
		dst string
	}
	_, err := os.Create("Test1.txt")
	assert.NoError(t, err)

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate Copy with valid data",
			args: args{
				src: "Test1.txt",
				dst: "Test2.txt",
			},
			wantErr: false,
		},
		{
			name: "Validate Copy with invalid data",
			args: args{
				src: "Test3.txt",
				dst: "Test2.txt",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Copy(tt.args.src, tt.args.dst); (err != nil) != tt.wantErr {
				t.Errorf("Copy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	os.Remove("Test1.txt")
	os.Remove("Test2.txt")
}

func TestGetDirFileContents(t *testing.T) {
	type args struct {
		dir     string
		pattern string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate GetDirFileContents with valid data",
			args: args{
				dir:     "../pkg",
				pattern: "*.*",
			},
			wantErr: false,
		},
		{
			name: "Validate GetDirFileContents with invalid data",
			args: args{
				dir:     "../test_pkg",
				pattern: "*.*",
			},
			wantErr: true,
		},
		{
			name: "Validate GetDirFileContents with empty pattern",
			args: args{
				dir:     "../pkg",
				pattern: "",
			},
			wantErr: false,
		},
		{
			name: "Validate GetDirFileContents with invalid pattern",
			args: args{
				dir:     "../pkg",
				pattern: "test.go",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetDirFileContents(tt.args.dir, tt.args.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDirFileContents() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestChownDirForUser(t *testing.T) {
	type args struct {
		serviceUserName string
		configDir       string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Invalid ChownDirForUser",
			args: args{
				serviceUserName: "user1",
				configDir:       "../pkg",
			},
			wantErr: true,
		},
		{
			name: "Valid ChownDirForUser",
			args: args{
				serviceUserName: "root",
				configDir:       "../pkg",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ChownDirForUser(tt.args.serviceUserName, tt.args.configDir); (err != nil) != tt.wantErr {
				t.Errorf("ChownDirForUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
