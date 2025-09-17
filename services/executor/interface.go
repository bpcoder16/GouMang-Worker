package executor

import (
	"context"
	"goumang-worker/services/pb"
)

// Executor 任务执行器接口
type Executor interface {
	// Execute 执行任务
	Execute(ctx context.Context, params string, stream pb.Task_RunServer) error
}

// Creator 执行器创建函数类型
type Creator func() Executor

// Factory 执行器工厂接口
type Factory interface {
	// CreateExecutor 创建指定类型的执行器
	CreateExecutor(method pb.Method) (Executor, error)

	// SupportedMethods 返回支持的执行方法列表
	SupportedMethods() []pb.Method

	// RegisterExecutor 注册执行器创建函数
	RegisterExecutor(method pb.Method, creator Creator)

	// IsSupported 查看执行器创建函数是否存在
	IsSupported(method pb.Method) bool
}
