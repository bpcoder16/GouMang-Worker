package shell

import (
	"bufio"
	"context"
	"fmt"
	"goumang-worker/services/executor"
	"goumang-worker/services/pb"
	"goumang-worker/services/security"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/bpcoder16/Chestnut/v2/core/gtask"
	"github.com/bpcoder16/Chestnut/v2/logit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// init 自动注册 Shell 执行器到默认工厂
func init() {
	executor.RegisterExecutor(pb.Method_SHELL, NewExecutor)
}

const (
	bufSize = 1000
)

// Executor shell 命令执行器
type Executor struct {
	validator security.CommandValidator
	once      sync.Once
}

// NewExecutor 创建新的 shell 执行器
func NewExecutor() executor.Executor {
	return &Executor{}
}

// Execute 执行 shell 命令
func (e *Executor) Execute(ctx context.Context, command string, stream pb.Task_RunServer) error {
	command = strings.TrimSpace(command)
	if len(command) == 0 {
		return status.Error(codes.InvalidArgument, "empty command")
	}

	// 初始化验证器（只初始化一次）
	e.once.Do(func() {
		validator, err := security.NewValidator("/conf/security.yaml")
		if err != nil {
			logit.Context(ctx).ErrorW("failed to create security validator", "error", err)
			// 如果验证器创建失败，使用禁用的验证器
			e.validator = &disabledValidator{}
		} else {
			e.validator = validator
		}
	})

	// 验证命令
	if e.validator != nil && e.validator.IsEnabled() {
		result := e.validator.ValidateCommand(ctx, command)
		if !result.Valid {
			return status.Error(codes.PermissionDenied, fmt.Sprintf("command not allowed: %s", result.Reason))
		}
		// 使用标准化的命令
		if result.NormalizedCommand != "" {
			command = result.NormalizedCommand
		}
	}

	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // 独立进程组，便于杀掉整个子进程组
	}

	// 获取 stdout 和 stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("failed to get stdout pipe: %v", err))
	}
	defer func() {
		if errS := stdoutPipe.Close(); errS != nil && !strings.Contains(errS.Error(), "already closed") {
			logit.Context(ctx).WarnW("stdoutPipe.Close().Err", errS)
		}
	}()

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("failed to get stderr pipe: %v", err))
	}
	defer func() {
		if errS := stderrPipe.Close(); errS != nil && !strings.Contains(errS.Error(), "already closed") {
			logit.Context(ctx).WarnW("stderrPipe.Close().Err", errS)
		}
	}()

	// 启动命令
	if err = cmd.Start(); err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("start command failed: %v", err))
	}

	// 定义缓冲 channel
	stdoutCh := make(chan string, bufSize)
	stderrCh := make(chan string, bufSize)

	g, gCtx := gtask.WithContext(ctx)

	// 读取 stdout
	g.Go(func() error {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			select {
			case stdoutCh <- scanner.Text():
			case <-gCtx.Done():
				return nil
			}
		}
		if errS := scanner.Err(); errS != nil && errS != io.EOF {
			logit.Context(ctx).WarnW("stdout.scanner.Err", errS)
			stdoutCh <- fmt.Sprintf("stdout read error: %v", errS)
		}
		close(stdoutCh)
		return nil
	})

	// 读取 stderr
	g.Go(func() error {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			select {
			case stderrCh <- scanner.Text():
			case <-gCtx.Done():
				return nil
			}
		}
		if errS := scanner.Err(); errS != nil && errS != io.EOF {
			logit.Context(ctx).WarnW("stderr.scanner.Err", errS)
			stderrCh <- fmt.Sprintf("stderr read error: %v", errS)
		}
		close(stderrCh)
		return nil
	})

	// 发送流
	sendErrCh := make(chan error, 1)
	g.Go(func() error {
		for stdoutCh != nil || stderrCh != nil {
			select {
			case line, ok := <-stdoutCh:
				if !ok {
					stdoutCh = nil
					continue
				}
				if errS := stream.Send(&pb.TaskResponse{Content: &pb.TaskResponse_Output{Output: line}}); errS != nil {
					logit.Context(gCtx).WarnW("stdout.stream.Send.Err", errS)
					sendErrCh <- errS
					return nil
				}
			case line, ok := <-stderrCh:
				if !ok {
					stderrCh = nil
					continue
				}
				if errS := stream.Send(&pb.TaskResponse{Content: &pb.TaskResponse_Error{Error: line}}); errS != nil {
					logit.Context(gCtx).WarnW("stderr.stream.Send.Err", errS)
					sendErrCh <- errS
					return nil
				}
			}
		}
		sendErrCh <- nil
		return nil
	})

	g.Go(func() error {
		select {
		case <-gCtx.Done():
			if errK := e.killProcessGroup(ctx, cmd); errK != nil {
				logit.Context(ctx).WarnW("killProcessGroup.Err", errK)
			}
			return status.Error(codes.Internal, fmt.Sprintf("command canceled or timeout: %v", gCtx.Err()))
		case errS := <-sendErrCh:
			if errS != nil {
				if errK := e.killProcessGroup(ctx, cmd); errK != nil {
					logit.Context(ctx).WarnW("killProcessGroup.Err", errK)
				}
				return status.Error(codes.Internal, fmt.Sprintf("failed to send output: %v", errS))
			}
		}
		return nil
	})

	g.Go(func() error {
		// 等待命令退出
		if errC := cmd.Wait(); errC != nil {
			logit.Context(ctx).WarnW("cmd.Wait.Err", errC)
			return status.Error(codes.Internal, fmt.Sprintf("command exited with error: %v", errC))
		}
		return nil
	})

	return g.Wait()
}

// killProcessGroup 杀死进程组
func (e *Executor) killProcessGroup(ctx context.Context, cmd *exec.Cmd) error {
	if cmd.Process == nil || cmd.Process.Pid <= 0 {
		return nil
	}

	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to kill process group %d: %w", cmd.Process.Pid, err)
	}

	logit.Context(ctx).InfoW("process group killed pid", cmd.Process.Pid)
	return nil
}

// disabledValidator 禁用的验证器实现
type disabledValidator struct{}

func (d *disabledValidator) ValidateCommand(_ context.Context, command string) *security.ValidationResult {
	return &security.ValidationResult{
		Valid:             true,
		NormalizedCommand: command,
	}
}

func (d *disabledValidator) IsEnabled() bool {
	return false
}

func (d *disabledValidator) Reload() error {
	return nil
}
