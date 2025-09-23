package security

// Config 安全配置结构
type Config struct {
	Security struct {
		EnableValidation bool `yaml:"enableValidation"`

		CommandParsing CommandParsingConfig `yaml:"commandParsing"`

		Logging LoggingConfig `yaml:"logging"`
	} `yaml:"security"`
}

// CommandParsingConfig 命令解析配置
type CommandParsingConfig struct {
	AllowPipes       bool `yaml:"allowPipes"`
	AllowRedirection bool `yaml:"allowRedirection"`
	AllowChaining    bool `yaml:"allowChaining"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	LogDeniedCommands  bool `yaml:"logDeniedCommands"`
	LogAllowedCommands bool `yaml:"logAllowedCommands"`
}
