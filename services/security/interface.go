package security

import "context"

// ValidationResult 验证结果
type ValidationResult struct {
	// 是否通过验证
	Valid bool
	// 验证失败原因
	Reason string
	// 验证通过后的标准化命令
	NormalizedCommand string
}

// CommandValidator 命令验证器接口
type CommandValidator interface {
	// ValidateCommand 验证命令是否允许执行
	ValidateCommand(ctx context.Context, command string) *ValidationResult

	// IsEnabled 检查验证器是否启用
	IsEnabled() bool

	// Reload 重新加载配置
	Reload() error
}