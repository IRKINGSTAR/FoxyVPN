package main

import (
	"github.com/sagernet/sing-box/experimental/libbox"
	_ "github.com/sagernet/sing-box/include"
)

func checkConfig(content string) error {
	return libbox.CheckConfig(content)
}
