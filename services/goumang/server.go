package goumang

import (
	"context"
	"fmt"
	"goumang-worker/services/executor"
	"goumang-worker/services/pb"
	"time"

	// 导入执行器包以触发自动注册
	_ "goumang-worker/services/executor/shell"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultTimeoutMinutes = 10
	maxTimeoutMinutes     = 60
)

type Server struct {
	pb.UnimplementedTaskServer
}

// NewServer 创建服务器
func NewServer() *Server {
	return &Server{}
}

func (s *Server) RegisterService(serviceRegistrar grpc.ServiceRegistrar) {
	pb.RegisterTaskServer(serviceRegistrar, s)
}

func (s *Server) Run(req *pb.TaskRequest, stream pb.Task_RunServer) error {
	timeout := s.getTimeout(req.Timeout)
	if timeout > maxTimeoutMinutes*time.Minute {
		timeout = maxTimeoutMinutes * time.Minute
	}
	ctx, cancel := context.WithTimeout(stream.Context(), timeout)
	defer cancel()

	var err error

	// 使用工厂创建执行器
	exec, createErr := executor.CreateExecutor(req.Method)
	if createErr != nil {
		err = status.Error(codes.InvalidArgument, fmt.Sprintf("unsupported method %s: %v", req.Method.String(), createErr))
	} else {
		err = exec.Execute(ctx, req.MethodParams, stream)
	}

	return err
}

func (s *Server) getTimeout(timeoutSec int32) time.Duration {
	if timeoutSec <= 0 {
		return defaultTimeoutMinutes * time.Minute
	}
	return time.Duration(timeoutSec) * time.Second
}
