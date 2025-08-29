package bootstrap

import (
	"context"

	"github.com/bpcoder16/Chestnut/v2/appconfig"
	"github.com/bpcoder16/Chestnut/v2/bootstrap"
)

func MustInit(ctx context.Context, config *appconfig.AppConfig) {
	bootstrap.MustInit(ctx, config)
}
