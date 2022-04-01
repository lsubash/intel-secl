/*
Copyright © 2021 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package constants

const (
	ExplicitServiceName = "ISecL K8s Controller"
)

const LogFilePath = "/var/log/isecl-k8s-controller/isecl-controller.log"

// Env param handles
const (
	LogLevelEnv             = "LOG_LEVEL"
	LogMaxLengthEnv         = "LOG_MAX_LENGTH"
	TaintUntrustedNodesEnv  = "TAINT_UNTRUSTED_NODES"
	TaintRegisteredNodesEnv = "TAINT_REGISTERED_NODES"
	TaintRebootedNodesEnv   = "TAINT_REBOOTED_NODES"
	TagPrefixEnv            = "TAG_PREFIX"
	KubeconfEnv             = "KUBECONF"
)

// Default values
const (
	LogLevelDefault             = "INFO"
	LogMaxLengthDefault         = 1500
	TagPrefixDefault            = "isecl."
	TaintUntrustedNodesDefault  = false
	TaintRegisteredNodesDefault = false
	TaintRebootedNodesDefault   = false
	FilePerms                   = 0664
	NodeRebooted                = "Rebooted"
	NodeRegistered              = "RegisteredNode"
	MasterNodeLabel             = "node-role.kubernetes.io/master"
)

const (
	WgName         = "iseclcontroller"
	MinThreadiness = 1
	ErrExitCode    = 1
)
