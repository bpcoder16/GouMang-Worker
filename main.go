package main

import (
	"context"
	"goumang-worker/bootstrap"
	"log"

	"github.com/bpcoder16/Chestnut/v2/appconfig"
	"github.com/bpcoder16/Chestnut/v2/core/cdefer"
)

func main() {
	config := appconfig.MustLoadAppConfig("/conf/app-server.yaml")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bootstrap.MustInit(ctx, config)
	defer cdefer.Defer()

	log.Println("server exit:", bootstrap.Start(ctx, config))
}
