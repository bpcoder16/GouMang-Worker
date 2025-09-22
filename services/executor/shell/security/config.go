package security

// Config 安全配置结构
type Config struct {
	Security struct {
		EnableValidation bool `yaml:"enableValidation"`

		AllowedPaths []AllowedPath `yaml:"allowedPaths"`

		AllowedInterpreters []AllowedInterpreter `yaml:"allowedInterpreters"`

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

// AllowedInterpreter 允许的解释器配置
type AllowedInterpreter struct {
	Name           string   `yaml:"name"`
	Executables    []string `yaml:"executables"`
	FileExtensions []string `yaml:"fileExtensions"`
	Description    string   `yaml:"description"`
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
