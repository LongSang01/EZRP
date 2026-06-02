package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"EZRP/internal/config"
	"EZRP/internal/socks5"
	"EZRP/internal/tunnel"

	log "github.com/sirupsen/logrus"
)

func main() {
	cfgPath := flag.String("c", "", "服务端配置文件路径(JSON)")
	logLevel := flag.String("log", "info", "日志级别: debug, info, warn, error")
	generateCfg := flag.Bool("gen-config", false, "生成默认服务端配置")
	flag.Parse()

	// 配置日志
	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", *logLevel)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05",
	})

	// 生成默认配置
	if *generateCfg {
		cfg := config.DefaultServerConfig()
		data, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(data))
		return
	}

	// 加载配置
	var cfg *config.ServerConfig
	if *cfgPath != "" {
		cfg, err = config.LoadServerConfig(*cfgPath)
		if err != nil {
			log.Fatalf("Load config: %v", err)
		}
	} else {
		cfg = config.DefaultServerConfig()
	}

	log.Infof("Server configuration:")
	log.Infof("  Tunnel: %s", cfg.TunnelAddr)
	log.Infof("  SOCKS5: %s", cfg.SocksAddr)
	log.Infof("  Token:  ****")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 启动隧道服务端
	tunnelSrv := tunnel.NewServer(cfg)
	if err := tunnelSrv.Start(ctx); err != nil {
		log.Fatalf("Start tunnel server: %v", err)
	}

	// 创建 SOCKS5 服务并基于隧道建立远程拨号器
	remoteDialer := func(ctx context.Context, target string) (net.Conn, error) {
		return tunnelSrv.Connect(target)
	}

	socksSrv := socks5.NewServer(cfg, remoteDialer)
	if err := socksSrv.Start(ctx); err != nil {
		log.Fatalf("Start SOCKS5 server: %v", err)
	}

	log.Infof("Server is running. Press Ctrl+C to stop.")

	// 等待关机信号
	<-sigCh
	log.Info("Shutting down...")
	socksSrv.Stop()
	tunnelSrv.Stop()
	log.Info("Server stopped.")
}
