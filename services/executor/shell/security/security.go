package security

import (
	"context"
	"fmt"
	"path"

	"github.com/bpcoder16/Chestnut/v2/appconfig/env"
)

// 包级别的验证器实例
var globalValidator CommandValidator

// getDefaultConfigPath 获取默认配置路径
func getDefaultConfigPath() string {
	return path.Join(env.ConfigDirPath(), "shell-security.yaml")
}

// init 包初始化时创建验证器
func init() {
	// 严格模式：配置错误时直接 panic，确保安全配置的正确性
	configPath := getDefaultConfigPath()
	v, err := NewValidator(configPath)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize shell security validator: %v\nPlease ensure %s exists and is properly configured", err, configPath))
	}

	globalValidator = v
}

// ValidateCommand 验证命令是否允许执行
// 这是包的主要对外接口，简化了调用方式
func ValidateCommand(ctx context.Context, command string) *ValidationResult {
	return globalValidator.ValidateCommand(ctx, command)
}

// IsEnabled 检查验证器是否启用
func IsEnabled() bool {
	return globalValidator.IsEnabled()
}