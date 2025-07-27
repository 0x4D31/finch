package main

import "github.com/0x4D31/finch/internal/proxy"

const (
	defaultConfigFile     = "configs/finch.hcl"
	defaultUpstream       = "http://localhost:8080"
	defaultRuleFile       = "configs/default.rules.hcl"
	defaultAccessLog      = "events.jsonl"
	defaultListenBind     = "0.0.0.0:8443"
	defaultProxyCacheSize = proxy.DefaultProxyCacheSize
)
