/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package keycache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var t1 = time.Now()
var expTimeDelta, _ = time.ParseDuration("5m")
var t2 = t1.Add(expTimeDelta)

func TestGetAndStore(t *testing.T) {
	log.Trace("keycache/keycache_test:TestGetAndStore() Entering")
	defer log.Trace("keycache/keycache_test:TestGetAndStore() Leaving")
	assert := assert.New(t)
	cache := NewCache()

	key := Key{"keyid", []byte{0, 1, 2, 3}, t1, t2}
	cache.Store("foobar", key)
	actual, exists := cache.Get("foobar")
	assert.True(exists)
	assert.Equal(key, actual)
}

func TestGetNone(t *testing.T) {
	log.Trace("keycache/keycache_test:TestGetNone() Entering")
	defer log.Trace("keycache/keycache_test:TestGetNone() Leaving")
	assert := assert.New(t)
	cache := NewCache()
	actual, exists := cache.Get("foobar")
	assert.False(exists)
	assert.Zero(actual)
}

func TestOverwrite(t *testing.T) {
	log.Trace("keycache/keycache_test:TestOverwrite() Entering")
	defer log.Trace("keycache/keycache_test:TestOverwrite() Leaving ")
	assert := assert.New(t)
	cache := NewCache()
	key1 := Key{"foo", []byte{0, 1, 2, 3}, t1, t2}
	key2 := Key{"bar", []byte{4, 5, 6, 7}, t1, t2}
	cache.Store("foobar", key1)
	cache.Store("foobar", key2)
	actual, exists := cache.Get("foobar")
	assert.True(exists)
	assert.Equal(key2, actual)
}

func TestGet(t *testing.T) {

	testCache := Key{
		ID:      "1000",
		Bytes:   []byte("testkey"),
		Created: time.Now(),
		Expired: time.Now(),
	}

	global.keys = map[string]Key{"key1": testCache}

	type args struct {
		imageID string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Should be successful",
			args: args{
				imageID: "key1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyRetrieved, ok := Get(tt.args.imageID)
			gKey := global.keys["key1"]
			if !ok {
				t.Errorf("wls/keycache:TestGet(): error = Key not found")
				return
			} else if ok && keyRetrieved.ID != gKey.ID {
				t.Errorf("wls/keycache:TestGet(): error = Key ID is not matching")
				return
			}
		})
	}
}

func TestStore(t *testing.T) {
	type args struct {
		imageID string
		key     Key
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Should be successful",
			args: args{
				imageID: "1000",
				key: Key{
					ID:    "1000",
					Bytes: []byte("testkey"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Store(tt.args.imageID, tt.args.key)
		})
	}
}
