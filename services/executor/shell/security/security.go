package security

import (
	"context"
	"fmt"

	"goumang-worker/services/security"
)

// 包级别的验证器实例
var globalValidator security.CommandValidator

// 默认配置路径
const defaultConfigPath = "/conf/security.yaml"

// init 包初始化时创建验证器
func init() {
	// 严格模式：配置错误时直接 panic，确保安全配置的正确性
	v, err := NewValidator(defaultConfigPath)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize shell security validator: %v\nPlease ensure %s exists and is properly configured", err, defaultConfigPath))
	}

	globalValidator = v
}

// ValidateCommand 验证命令是否允许执行
// 这是包的主要对外接口，简化了调用方式
func ValidateCommand(ctx context.Context, command string) *security.ValidationResult {
	return globalValidator.ValidateCommand(ctx, command)
}

// IsEnabled 检查验证器是否启用
func IsEnabled() bool {
	return globalValidator.IsEnabled()
}

// Reload 重新加载配置
func Reload() error {
	return globalValidator.Reload()
}