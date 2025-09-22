package security

// Config 安全配置结构
type Config struct {
	Security struct {
		EnableValidation bool `yaml:"enableValidation"`

		AllowedPaths []AllowedPath `yaml:"allowedPaths"`

		CommandParsing CommandParsingConfig `yaml:"commandParsing"`

		Logging LoggingConfig `yaml:"logging"`
	} `yaml:"security"`
}

// AllowedPath 允许的路径配置
type AllowedPath struct {
	Path        string `yaml:"path"`
	Description string `yaml:"description"`
	Recursive   bool   `yaml:"recursive"`
	MaxDepth    int    `yaml:"maxDepth"`
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
