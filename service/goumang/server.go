package goumang

import (
	"bufio"
	"context"
	"fmt"
	"goumang-worker/service/pb"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/bpcoder16/Chestnut/v2/core/gtask"
	"github.com/bpcoder16/Chestnut/v2/logit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const bufSize = 1000

type Server struct {
	pb.UnimplementedTaskServer
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) RegisterService(serviceRegistrar grpc.ServiceRegistrar) {
	pb.RegisterTaskServer(serviceRegistrar, s)
}

func (s *Server) Run(req *pb.TaskRequest, stream pb.Task_RunServer) error {
	timeout := time.Second * time.Duration(req.Timeout)
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(stream.Context(), timeout)
	defer cancel()
	switch req.Method {
	case pb.Method_SHELL:
		return s.execShell(ctx, req.MethodParams, stream)
	default:
		return status.Error(codes.InvalidArgument, "invalid method")
	}
}

func (s *Server) execShell(ctx context.Context, command string, stream pb.Task_RunServer) error {
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // 独立进程组，便于杀掉整个子进程组
	}

	// 获取 stdout 和 stderr
	var stdoutPipe, stderrPipe io.ReadCloser
	var err error
	if stdoutPipe, err = cmd.StdoutPipe(); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	if stderrPipe, err = cmd.StderrPipe(); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
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
			logit.Context(ctx).WarnW("stdout read error", errS.Error())
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
			logit.Context(ctx).WarnW("stderr read error", errS.Error())
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
					logit.Context(gCtx).WarnW("stdoutCh", "steam.Send error: "+errS.Error())
				}
			case line, ok := <-stderrCh:
				if !ok {
					stderrCh = nil
					continue
				}
				if errS := stream.Send(&pb.TaskResponse{Content: &pb.TaskResponse_Error{Error: line}}); errS != nil {
					logit.Context(gCtx).WarnW("stderrCh", "steam.Send error: "+errS.Error())
				}
			}
		}
		sendErrCh <- nil
		return nil
	})

	g.Go(func() error {
		select {
		case <-gCtx.Done():
			if cmd.Process != nil && cmd.Process.Pid > 0 {
				errSyscall := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				if errSyscall != nil {
					logit.Context(ctx).WarnW("ctx.Done().syscall.Kill", errSyscall.Error())
				}
			}
			return status.Error(codes.Internal, fmt.Sprintf("command canceled or timeout: %v", gCtx.Err()))
		case errS := <-sendErrCh:
			if errS != nil && cmd.Process != nil && cmd.Process.Pid > 0 {
				errSyscall := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				if errSyscall != nil {
					logit.Context(ctx).WarnW("<-sendErrCh.syscall.Kill", errSyscall.Error())
				}
				return status.Error(codes.Internal, fmt.Sprintf("failed to send output: %v", errS))
			}
		}
		return nil
	})

	g.Go(func() error {
		// 等待命令退出
		if errC := cmd.Wait(); errC != nil {
			logit.Context(ctx).WarnW("cmd.Wait()", errC.Error())
			return status.Error(codes.Internal, fmt.Sprintf("command exited with error: %v", errC))
		}
		return nil
	})

	return g.Wait()
}
