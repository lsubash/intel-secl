/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package wlagent

import (
	keyproviderpb "github.com/containers/ocicrypt/utils/keyprovider"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/proc"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	kpgrpc "github.com/intel-secl/intel-secl/v5/pkg/wlagent/keyprovider-grpc"
	"google.golang.org/grpc"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (a *App) runGRPCService() {
	log.Trace("server:runGRPCService() Entering")
	defer log.Trace("server:runGRPCService() Leaving")

	//check if the wlagent run directory path is already created
	if _, err := os.Stat(constants.RunDirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(constants.RunDirPath, constants.DefaultFilePerms); err != nil {
			log.WithError(err).Fatalf("server:runGRPCService() could not create directory: %s, err: %s", constants.RunDirPath, err)
		}
	}

	// When the socket is closed, the file handle on the socket file isn't handled.
	// This code is added to manually remove any stale socket file before the connection
	// is reopened; prevent error: bind address already in use
	// ensure that the socket file exists before removal
	if _, err := os.Stat(rpcSocketFilePath); err == nil {
		err = os.Remove(rpcSocketFilePath)
		if err != nil {
			log.WithError(err).Error("server:runGRPCService() Failed to remove socket file")
			os.Exit(1)
		}
	}

	serverAddr, err := net.ResolveUnixAddr("unix", rpcSocketFilePath)
	if err != nil {
		log.Errorf("Error while creating unix socket address %v", err)
		os.Exit(1)
	}

	lis, err := net.ListenUnix("unix", serverAddr)
	if err != nil {
		log.Errorf("Error while listening to unix socket %v", err)
		os.Exit(1)
	}

	s := grpc.NewServer()
	if s == nil {
		log.Errorf("Error creating grpc server")
		os.Exit(1)
	}
	keyproviderpb.RegisterKeyProviderServiceServer(s, &kpgrpc.GRPCServer{
		Config: a.config,
	})

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	// dispatch grpc go routine
	go func() {
		defer proc.TaskDone()
		if err := s.Serve(lis); err != nil {
			log.WithError(err).Fatal("server:runGRPCService() Failed to start GRPC server")
			stop <- syscall.SIGTERM
		}
	}()

	log.Info(commLogMsg.ServiceStart)
	// block until stop channel receives
	err = proc.WaitForQuitAndCleanup(10 * time.Second)
	if err != nil {
		log.WithError(err).Error("server:runGRPCService() Error while clean up")
	}
	s.GracefulStop()

	log.Info(commLogMsg.ServiceStop)

}
