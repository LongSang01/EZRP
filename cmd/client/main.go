package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"EZRP/internal/config"

	"EZRP/internal/tunnel"

	log "github.com/sirupsen/logrus"
)

func main() {
	cfgPath := flag.String("c", "", "客户端配置文件路径（JSON 格式）")
	logLevel := flag.String("log", "info", "日志级别: debug, info, warn, error")
	generateCfg := flag.Bool("gen-config", false, "生成默认客户端配置")
	flag.Parse()

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", *logLevel)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05",
	})

	if *generateCfg {
		cfg := config.DefaultClientConfig()
		data, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(data))
		return
	}

	var cfg *config.ClientConfig
	if *cfgPath != "" {
		cfg, err = config.LoadClientConfig(*cfgPath)
		if err != nil {
			log.Fatalf("Load config: %v", err)
		}
	} else {
		cfg = config.DefaultClientConfig()
	}

	log.Infof("Client configuration:")
	log.Infof("  Server: %s", cfg.ServerAddr)
	log.Infof("  Token:  ****")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	client := tunnel.NewClient(cfg)

	// 在协程中运行客户端（客户端内部处理重连逻辑）
	go func() {
		if err := client.Start(ctx); err != nil {
			log.Errorf("Client error: %v", err)
		}
	}()

	<-sigCh
	log.Info("Shutting down...")
	client.Stop()
	log.Info("Client stopped.")
}
