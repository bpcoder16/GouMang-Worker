package config

import (
	"path"
	"sync"

	"github.com/bpcoder16/Chestnut/v2/appconfig/env"
	"github.com/bpcoder16/Chestnut/v2/core/utils"
)

// ShellExecutorConfig Shell执行器配置
type ShellExecutorConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	EnableValidation bool `yaml:"enableValidation"`

	CommandParsing CommandParsingConfig `yaml:"commandParsing"`

	Logging LoggingConfig `yaml:"logging"`
}

// CommandParsingConfig 命令解析配置
type CommandParsingConfig struct {
	AllowPipes       bool `yaml:"allowPipes"`
	AllowRedirection bool `yaml:"allowRedirection"`
	AllowChaining    bool `yaml:"allowChaining"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	LogDeniedCommands  bool `yaml:"logDeniedCommands"`
	LogAllowedCommands bool `yaml:"logAllowedCommands"`
}

// Config Shell配置结构 - 统一的配置管理中心
type Config struct {
	Shell    ShellExecutorConfig `yaml:"shell"`
	Security SecurityConfig      `yaml:"security"`
}

var (
	globalConfig Config
	configOnce   sync.Once
)

// lazyLoadConfig 懒加载配置文件
func lazyLoadConfig() {
	configOnce.Do(func() {
		if err := utils.ParseFile(path.Join(env.ConfigDirPath(), "shell.yaml"), &globalConfig); err != nil {
			panic("loadConfig shell.yaml err:" + err.Error())
		}

		// 设置默认值
		if globalConfig.Shell.Command == "" {
			globalConfig.Shell.Command = "/bin/bash"
			globalConfig.Shell.Args = []string{"-c"}
		}
	})

	return
}

// GetShellConfig 获取 shell 执行器配置
func GetShellConfig() ShellExecutorConfig {
	lazyLoadConfig()
	return globalConfig.Shell
}

// GetSecurityConfig 获取安全配置
func GetSecurityConfig() SecurityConfig {
	lazyLoadConfig()
	return globalConfig.Security
}
