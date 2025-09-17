package bootstrap

import (
	"context"
	"goumang-worker/services/executor"
	"goumang-worker/services/goumang"
	"path"

	"github.com/bpcoder16/Chestnut/v2/appconfig"
	"github.com/bpcoder16/Chestnut/v2/appconfig/env"
	"github.com/bpcoder16/Chestnut/v2/bootstrap"
	"github.com/bpcoder16/Chestnut/v2/core/gtask"
	"github.com/bpcoder16/Chestnut/v2/logit"
	"github.com/bpcoder16/Chestnut/v2/modules/grpcserver"
)

func Start(ctx context.Context, config *appconfig.AppConfig) error {
	var g *gtask.Group
	g, ctx = gtask.WithContext(ctx)

	bootstrap.Start(ctx, config, g.Go)

	g.Go(func() error {
		// 记录支持的执行器方法
		logit.Context(ctx).InfoW("Available", "executors", "methods", executor.SupportedMethods())

		return grpcserver.NewManager(
			path.Join(env.ConfigDirPath(), "grpc.yaml"),
			goumang.NewServer(),
		).Run(ctx)
	})

	return g.Wait()
}
