package security

import (
	"context"
)

// 包级别的验证器实例
var globalValidator CommandValidator

// init 包初始化时创建验证器
func init() {
	// 使用统一配置管理，不再单独加载配置文件
	globalValidator = NewValidator()
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
