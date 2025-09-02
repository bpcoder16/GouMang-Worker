package goumang

import (
	"context"
	"goumang-worker/services/pb"
	"time"

	"github.com/bpcoder16/Chestnut/v2/logit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	bufSize               = 1000
	defaultTimeoutMinutes = 10
	maxTimeoutMinutes     = 60
)

type MethodService interface {
	Method() pb.Method
	Run(ctx context.Context, params string, stream pb.Task_RunServer) error
}
type Server struct {
	pb.UnimplementedTaskServer
	methodServiceMap map[pb.Method]MethodService
}

func NewServer(methodServiceList ...MethodService) *Server {
	server := &Server{
		methodServiceMap: make(map[pb.Method]MethodService, 20),
	}
	for _, service := range methodServiceList {
		server.methodServiceMap[service.Method()] = service
	}
	return server
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
	if methodService, isExist := s.methodServiceMap[req.Method]; isExist {
		err = methodService.Run(ctx, req.MethodParams, stream)
	} else {
		err = status.Error(codes.InvalidArgument, "unsupported method: "+req.Method.String())
	}
	logit.Context(ctx).InfoW("task", "completed", "method", req.Method.String(), "taskId", req.RunTaskId, "error", err)
	return err
}

func (s *Server) getTimeout(timeoutSec int32) time.Duration {
	if timeoutSec <= 0 {
		return defaultTimeoutMinutes * time.Minute
	}
	return time.Duration(timeoutSec) * time.Second
}
