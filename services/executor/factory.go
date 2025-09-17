package executor

import (
	"fmt"
	"goumang-worker/services/pb"
	"sync"
)

// executorFactory 执行器工厂实现
type executorFactory struct {
	creators map[pb.Method]Creator
	mu       sync.RWMutex
}

// NewFactory 创建新的执行器工厂
func NewFactory() Factory {
	return &executorFactory{
		creators: make(map[pb.Method]Creator),
	}
}

// CreateExecutor 创建指定类型的执行器
func (f *executorFactory) CreateExecutor(method pb.Method) (Executor, error) {
	f.mu.RLock()
	creator, exists := f.creators[method]
	f.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unsupported executor method: %v", method)
	}

	return creator(), nil
}

// SupportedMethods 返回支持的执行方法列表
func (f *executorFactory) SupportedMethods() []pb.Method {
	f.mu.RLock()
	defer f.mu.RUnlock()

	methods := make([]pb.Method, 0, len(f.creators))
	for method := range f.creators {
		methods = append(methods, method)
	}
	return methods
}

// RegisterExecutor 注册执行器创建函数
func (f *executorFactory) RegisterExecutor(method pb.Method, creator Creator) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.creators[method]; exists {
		panic(fmt.Errorf("executor method %v is already registered", method))
	}

	f.creators[method] = creator
}

func (f *executorFactory) IsSupported(method pb.Method) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, exists := f.creators[method]
	return exists
}

// GetCreator 获取指定方法的创建函数（用于测试）
func (f *executorFactory) GetCreator(method pb.Method) (Creator, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	creator, exists := f.creators[method]
	return creator, exists
}

// 全局默认工厂实例
var defaultFactory Factory

// init 初始化默认工厂
func init() {
	defaultFactory = NewFactory()
}

// DefaultFactory 获取默认工厂实例
func DefaultFactory() Factory {
	return defaultFactory
}

// CreateExecutor 使用默认工厂创建执行器
func CreateExecutor(method pb.Method) (Executor, error) {
	return defaultFactory.CreateExecutor(method)
}

// SupportedMethods 获取默认工厂支持的方法
func SupportedMethods() []pb.Method {
	return defaultFactory.SupportedMethods()
}

// RegisterExecutor 在默认工厂中注册执行器
func RegisterExecutor(method pb.Method, creator Creator) {
	defaultFactory.RegisterExecutor(method, creator)
}

// IsSupported 检查默认工厂是否支持指定方法
func IsSupported(method pb.Method) bool {
	if factory, ok := defaultFactory.(*executorFactory); ok {
		return factory.IsSupported(method)
	}
	return false
}
