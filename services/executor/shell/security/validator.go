package security

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/bpcoder16/Chestnut/v2/core/utils"
	"github.com/bpcoder16/Chestnut/v2/logit"
	"mvdan.cc/sh/v3/syntax"
)

// validator 命令验证器实现
type validator struct {
	config *Config
	mu     sync.RWMutex
}

// NewValidator 创建新的命令验证器
func NewValidator(configPath string) (CommandValidator, error) {
	v := &validator{}
	if err := v.loadConfig(configPath); err != nil {
		return nil, fmt.Errorf("failed to load security config: %w", err)
	}
	return v, nil
}

// IsEnabled 检查验证器是否启用
func (v *validator) IsEnabled() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.config != nil && v.config.Security.EnableValidation
}

// loadConfig 加载配置文件
func (v *validator) loadConfig(configPath string) error {
	config := &Config{}

	// 使用 Chestnut 框架的 utils.ParseFile 方式
	if err := utils.ParseFile(configPath, config); err != nil {
		return fmt.Errorf("failed to load config from %s: %w", configPath, err)
	}

	v.mu.Lock()
	v.config = config
	v.mu.Unlock()

	return nil
}

// ValidateCommand 验证命令是否允许执行
func (v *validator) ValidateCommand(ctx context.Context, command string) *ValidationResult {
	if !v.IsEnabled() {
		return &ValidationResult{
			Valid:             true,
			NormalizedCommand: command,
		}
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	// 清理命令
	command = strings.TrimSpace(command)
	if command == "" {
		return &ValidationResult{
			Valid:  false,
			Reason: "empty command",
		}
	}

	// 一次性解析命令语法树
	parser := syntax.NewParser()
	prog, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		// 解析失败时，为了安全起见认为是危险命令
		reason := fmt.Sprintf("command parsing failed: %v", err)
		v.logDeniedCommand(ctx, reason)
		return &ValidationResult{Valid: false, Reason: reason}
	}

	// 使用已解析的AST进行危险模式检查
	if result := v.checkDangerousPatternsWithAST(ctx, prog); !result.Valid {
		return result
	}

	// 兜底验证：默认拒绝所有未明确允许的命令
	reason := "command not in whitelist - default deny policy"
	v.logDeniedCommand(ctx, reason)
	return &ValidationResult{
		Valid:  false,
		Reason: reason,
	}
}

// logDeniedCommand 记录被拒绝的命令
func (v *validator) logDeniedCommand(ctx context.Context, reason string) {
	if v.config.Security.Logging.LogDeniedCommands {
		logit.Context(ctx).WarnW(
			"logType", "command denied",
			"reason", reason,
		)
	}
}

// checkDangerousPatternsWithAST 使用已解析的AST检查危险模式
func (v *validator) checkDangerousPatternsWithAST(ctx context.Context, prog *syntax.File) *ValidationResult {
	// 检查命令替换语法（$() 和反引号） - 强制禁止
	if result := v.checkCommandSubstitution(ctx, prog); !result.Valid {
		return result
	}

	// 检查后台执行（& 符号） - 强制禁止
	// TODO 考虑是否要禁掉 nohup 命令
	if result := v.checkBackgroundExecution(ctx, prog); !result.Valid {
		return result
	}

	// 检查管道 - 使用语法树精确检测
	// TODO 需要考虑管道后的 grep 处理，需要增加 --line-buffered
	if !v.config.Security.CommandParsing.AllowPipes {
		if v.hasPipes(prog) {
			reason := "pipes not allowed"
			v.logDeniedCommand(ctx, reason)
			return &ValidationResult{Valid: false, Reason: reason}
		}
	}

	// 检查重定向 - 使用语法树精确检测
	if !v.config.Security.CommandParsing.AllowRedirection {
		if v.hasRedirection(prog) {
			reason := "redirection not allowed"
			v.logDeniedCommand(ctx, reason)
			return &ValidationResult{Valid: false, Reason: reason}
		}
	}

	// 检查命令链接 - 使用语法树精确检测
	if !v.config.Security.CommandParsing.AllowChaining {
		if v.hasChaining(prog) {
			reason := "command chaining not allowed"
			v.logDeniedCommand(ctx, reason)
			return &ValidationResult{Valid: false, Reason: reason}
		}
	}

	return &ValidationResult{Valid: true}
}

// hasPipes 从已解析的AST检测是否包含管道
func (v *validator) hasPipes(prog *syntax.File) bool {
	hasPipe := false
	syntax.Walk(prog, func(node syntax.Node) bool {
		// 检查 BinaryCmd 节点（管道的主要表示方式）
		if binary, ok := node.(*syntax.BinaryCmd); ok {
			if binary.Op == syntax.Pipe {
				hasPipe = true
				return false
			}
		}
		return true
	})

	return hasPipe
}

// hasRedirection 从已解析的AST检测是否包含重定向
func (v *validator) hasRedirection(prog *syntax.File) bool {
	hasRedir := false
	syntax.Walk(prog, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.Redirect); ok {
			hasRedir = true
			return false // 停止遍历
		}
		return true // 继续遍历
	})

	return hasRedir
}

// hasBackground 从已解析的AST检测是否包含后台执行
func (v *validator) hasBackground(prog *syntax.File) bool {
	hasBg := false
	syntax.Walk(prog, func(node syntax.Node) bool {
		// 检查语句节点的后台标志
		if stmt, ok := node.(*syntax.Stmt); ok {
			if stmt.Background {
				hasBg = true
				return false
			}
		}
		return true
	})

	return hasBg
}

// hasChaining 从已解析的AST检测是否包含命令链接
func (v *validator) hasChaining(prog *syntax.File) bool {
	hasChain := false
	syntax.Walk(prog, func(node syntax.Node) bool {
		// 检查 BinaryCmd 节点（命令链接的主要表示方式）
		if binary, ok := node.(*syntax.BinaryCmd); ok {
			switch binary.Op {
			case syntax.AndStmt, syntax.OrStmt: // && 和 ||
				hasChain = true
				return false
			default:
				// 其他类型的 BinaryCmd（如管道）不算命令链接
			}
		}
		// 检查是否有多个语句（用 ; 分隔）
		if file, ok := node.(*syntax.File); ok {
			if len(file.Stmts) > 1 {
				hasChain = true
				return false
			}
		}
		return true
	})

	return hasChain
}

// checkCommandSubstitution 检查命令替换（$() 和反引号）
func (v *validator) checkCommandSubstitution(ctx context.Context, prog *syntax.File) *ValidationResult {
	hasCmdSubst := false
	var cmdSubstType string

	syntax.Walk(prog, func(node syntax.Node) bool {
		// 检查命令替换节点 $()
		if cmdSubst, ok := node.(*syntax.CmdSubst); ok {
			hasCmdSubst = true
			if cmdSubst.Backquotes {
				cmdSubstType = "backticks"
			} else {
				cmdSubstType = "dollar-parentheses"
			}
			return false // 停止遍历
		}
		return true
	})

	if hasCmdSubst {
		reason := fmt.Sprintf("command substitution not allowed: %s", cmdSubstType)
		v.logDeniedCommand(ctx, reason)
		return &ValidationResult{Valid: false, Reason: reason}
	}

	return &ValidationResult{Valid: true}
}

// checkBackgroundExecution 检查后台执行（& 符号）
func (v *validator) checkBackgroundExecution(ctx context.Context, prog *syntax.File) *ValidationResult {
	hasBackground := v.hasBackground(prog)

	if hasBackground {
		reason := "background execution not allowed"
		v.logDeniedCommand(ctx, reason)
		return &ValidationResult{Valid: false, Reason: reason}
	}

	return &ValidationResult{Valid: true}
}
