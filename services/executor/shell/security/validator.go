package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

	// 检查危险模式
	if result := v.checkDangerousPatterns(ctx, command); !result.Valid {
		return result
	}

	//// 解析命令
	//parsedCmd, err := v.parseCommand(command)
	//if err != nil {
	//	return &ValidationResult{
	//		Valid:  false,
	//		Reason: fmt.Sprintf("failed to parse command: %v", err),
	//	}
	//}
	//
	//// 验证命令
	//if result := v.validateParsedCommand(ctx, parsedCmd); !result.Valid {
	//	return result
	//}
	//
	//// 记录允许的命令
	//if v.config.Security.Logging.LogAllowedCommands {
	//	logit.Context(ctx).InfoW("command allowed", "command", command)
	//}

	return &ValidationResult{
		Valid:             true,
		NormalizedCommand: command,
	}
}

// logDeniedCommand 记录被拒绝的命令
func (v *validator) logDeniedCommand(ctx context.Context, reason string, cmd *ParsedCommand) {
	if v.config.Security.Logging.LogDeniedCommands {
		logit.Context(ctx).WarnW(
			"logType", "command denied",
			"reason", reason,
			"interpreter", cmd.Interpreter,
			"filePath", cmd.FilePath,
			"args", cmd.Args,
		)
	}
}

// checkDangerousPatterns 检查危险模式
func (v *validator) checkDangerousPatterns(ctx context.Context, command string) *ValidationResult {
	// 统一解析命令语法树，避免重复解析
	parser := syntax.NewParser()
	prog, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		// 解析失败时，为了安全起见认为是危险命令
		reason := fmt.Sprintf("command parsing failed: %v", err)
		v.logDeniedCommand(ctx, reason, &ParsedCommand{})
		return &ValidationResult{Valid: false, Reason: reason}
	}

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
			v.logDeniedCommand(ctx, reason, &ParsedCommand{})
			return &ValidationResult{Valid: false, Reason: reason}
		}
	}

	// 检查重定向 - 使用语法树精确检测
	if !v.config.Security.CommandParsing.AllowRedirection {
		if v.hasRedirection(prog) {
			reason := "redirection not allowed"
			v.logDeniedCommand(ctx, reason, &ParsedCommand{})
			return &ValidationResult{Valid: false, Reason: reason}
		}
	}

	// 检查命令链接 - 使用语法树精确检测
	if !v.config.Security.CommandParsing.AllowChaining {
		if v.hasChaining(prog) {
			reason := "command chaining not allowed"
			v.logDeniedCommand(ctx, reason, &ParsedCommand{})
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
		v.logDeniedCommand(ctx, reason, &ParsedCommand{})
		return &ValidationResult{Valid: false, Reason: reason}
	}

	return &ValidationResult{Valid: true}
}

// checkBackgroundExecution 检查后台执行（& 符号）
func (v *validator) checkBackgroundExecution(ctx context.Context, prog *syntax.File) *ValidationResult {
	hasBackground := v.hasBackground(prog)

	if hasBackground {
		reason := "background execution not allowed"
		v.logDeniedCommand(ctx, reason, &ParsedCommand{})
		return &ValidationResult{Valid: false, Reason: reason}
	}

	return &ValidationResult{Valid: true}
}

///////////////////////////////////////////////////////////////////////////////////

// ParsedCommand 解析后的命令结构
type ParsedCommand struct {
	Interpreter string   // 解释器 (python, php, bash 等)
	Args        []string // 参数列表
	FilePath    string   // 目标文件路径
}

// parseCommand 解析命令
func (v *validator) parseCommand(command string) (*ParsedCommand, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	cmd := &ParsedCommand{
		Interpreter: parts[0],
		Args:        parts[1:],
	}

	// 查找文件路径
	for _, arg := range cmd.Args {
		// 跳过选项参数
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// 找到第一个非选项参数作为文件路径
		cmd.FilePath = arg
		break
	}

	return cmd, nil
}

// validateParsedCommand 验证解析后的命令
func (v *validator) validateParsedCommand(ctx context.Context, cmd *ParsedCommand) *ValidationResult {
	// 验证解释器
	interpreter := v.findMatchingInterpreter(cmd.Interpreter)
	if interpreter == nil {
		reason := fmt.Sprintf("interpreter '%s' not allowed", cmd.Interpreter)
		v.logDeniedCommand(ctx, reason, cmd)
		return &ValidationResult{
			Valid:  false,
			Reason: reason,
		}
	}

	// 如果没有文件路径，只允许特定解释器的内置命令
	if cmd.FilePath == "" {
		// 对于二进制执行器，解释器本身就是要执行的命令
		if interpreter.Name == "binary" {
			return v.validateBinaryExecutable(ctx, cmd.Interpreter)
		}
		// 其他解释器需要指定文件
		reason := "missing file path"
		v.logDeniedCommand(ctx, reason, cmd)
		return &ValidationResult{
			Valid:  false,
			Reason: reason,
		}
	}

	// 验证文件路径
	return v.validateFilePath(ctx, cmd.FilePath, interpreter)
}

// findMatchingInterpreter 查找匹配的解释器配置
func (v *validator) findMatchingInterpreter(executable string) *AllowedInterpreter {
	for _, interpreter := range v.config.Security.AllowedInterpreters {
		// 检查可执行文件名
		for _, exec := range interpreter.Executables {
			if exec == executable {
				return &interpreter
			}
		}
		// 对于二进制文件，直接匹配名称
		if interpreter.Name == "binary" && len(interpreter.Executables) == 0 {
			return &interpreter
		}
	}
	return nil
}

// validateBinaryExecutable 验证二进制可执行文件
func (v *validator) validateBinaryExecutable(ctx context.Context, executable string) *ValidationResult {
	// 验证可执行文件路径是否在允许的目录中
	for _, allowedPath := range v.config.Security.AllowedPaths {
		fullPath := filepath.Join(allowedPath.Path, executable)
		if v.isPathAllowed(fullPath, &allowedPath) {
			return &ValidationResult{Valid: true}
		}
	}

	reason := fmt.Sprintf("binary executable '%s' not in allowed paths", executable)
	v.logDeniedCommand(ctx, reason, &ParsedCommand{Interpreter: executable})
	return &ValidationResult{
		Valid:  false,
		Reason: reason,
	}
}

// validateFilePath 验证文件路径
func (v *validator) validateFilePath(ctx context.Context, filePath string, interpreter *AllowedInterpreter) *ValidationResult {
	// 转换为绝对路径
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		reason := fmt.Sprintf("invalid file path '%s': %v", filePath, err)
		v.logDeniedCommand(ctx, reason, &ParsedCommand{FilePath: filePath})
		return &ValidationResult{
			Valid:  false,
			Reason: reason,
		}
	}

	// 检查文件是否存在
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		reason := fmt.Sprintf("file does not exist: %s", absPath)
		v.logDeniedCommand(ctx, reason, &ParsedCommand{FilePath: filePath})
		return &ValidationResult{
			Valid:  false,
			Reason: reason,
		}
	}

	// 检查文件扩展名
	if !v.isValidFileExtension(absPath, interpreter) {
		reason := fmt.Sprintf("file extension not allowed for interpreter '%s': %s", interpreter.Name, absPath)
		v.logDeniedCommand(ctx, reason, &ParsedCommand{FilePath: filePath})
		return &ValidationResult{
			Valid:  false,
			Reason: reason,
		}
	}

	// 检查路径是否在白名单中
	if !v.isFileInAllowedPaths(absPath) {
		reason := fmt.Sprintf("file path not in allowed directories: %s", absPath)
		v.logDeniedCommand(ctx, reason, &ParsedCommand{FilePath: filePath})
		return &ValidationResult{
			Valid:  false,
			Reason: reason,
		}
	}

	return &ValidationResult{Valid: true}
}

// isValidFileExtension 检查文件扩展名是否有效
func (v *validator) isValidFileExtension(filePath string, interpreter *AllowedInterpreter) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// 对于没有扩展名的二进制文件
	if interpreter.Name == "binary" && ext == "" {
		return true
	}

	for _, allowedExt := range interpreter.FileExtensions {
		if ext == allowedExt {
			return true
		}
	}
	return false
}

// isFileInAllowedPaths 检查文件是否在允许的路径中
func (v *validator) isFileInAllowedPaths(filePath string) bool {
	for _, allowedPath := range v.config.Security.AllowedPaths {
		if v.isPathAllowed(filePath, &allowedPath) {
			return true
		}
	}
	return false
}

// isPathAllowed 检查路径是否被允许
func (v *validator) isPathAllowed(filePath string, allowedPath *AllowedPath) bool {
	absAllowedPath, err := filepath.Abs(allowedPath.Path)
	if err != nil {
		return false
	}

	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}

	// 检查是否在允许的路径下
	relPath, err := filepath.Rel(absAllowedPath, absFilePath)
	if err != nil {
		return false
	}

	// 检查是否试图访问父目录
	if strings.HasPrefix(relPath, "..") {
		return false
	}

	// 如果不允许递归，文件必须在当前目录
	if !allowedPath.Recursive {
		return filepath.Dir(absFilePath) == absAllowedPath
	}

	// 检查递归深度
	if allowedPath.MaxDepth >= 0 {
		depth := len(strings.Split(relPath, string(filepath.Separator))) - 1
		if depth > allowedPath.MaxDepth {
			return false
		}
	}

	return true
}
