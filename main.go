package main

import (
    "bytes"
    "context"
    "embed"
    "encoding/json"
    "fmt"
    "html/template"
    "io"
    "io/fs"
    "log"
    "net/http"
    "strconv"
    "strings"
    "time"
    "sync"
    "os"
    "os/signal"
    "syscall"
    "runtime"
    "golang.org/x/time/rate"
    "github.com/bwmarrin/discordgo"
    "github.com/gin-contrib/static"
    "github.com/gin-gonic/gin"
    "github.com/spf13/viper"
    "github.com/shirou/gopsutil/cpu"
    "github.com/shirou/gopsutil/disk"
    "github.com/shirou/gopsutil/mem"
    "github.com/shirou/gopsutil/net"
    "github.com/joho/godotenv"
)

//go:embed views/*.html
var templateFS embed.FS
//go:embed public
var staticFS embed.FS

var (
    startTime   time.Time
    restartChan chan bool
)

type Config struct {
    Host       string `mapstructure:"host"`
    FileChannel string
    MaxFileSize struct {
        Human string `mapstructure:"human"`
        Byte  int64  `mapstructure:"byte"`
    } `mapstructure:"maxFileSize"`
    Analytics struct {
        Enabled     bool   `mapstructure:"enabled"`
        LogToDiscord bool   `mapstructure:"logToDiscord"`
    } `mapstructure:"analytics"`
    RateLimit struct {
        Enabled    bool   `mapstructure:"enabled"`
        Requests   int    `mapstructure:"requests"`
        PerSeconds int    `mapstructure:"perSeconds"`
        Message    string `mapstructure:"message"`
    } `mapstructure:"rateLimit"`
    ChannelID   string
    Token string
    Domain string
    Version string
    Port int
}

type RateLimiter struct {
    visitors map[string]*rate.Limiter
    mtx      sync.Mutex
    r        rate.Limit
    b        int
}
type App struct {
    Config     Config
    Discord    *DiscordService
    FileServer *FileServer
    RateLimiter *RateLimiter
    Router     *gin.Engine
    Logger *log.Logger
}

type DiscordService struct {
    Session *discordgo.Session
    Config  *Config
}

type FileServer struct {
    FS embed.FS
}

type FileHandler struct {
    Discord *DiscordService
    Config  *Config
}

type progressReader struct {
    reader   io.Reader
    size     int64
    progress chan int64
    read     int64
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
    return &RateLimiter{
        visitors: make(map[string]*rate.Limiter),
        r:        r,
        b:        b,
    }
}

func NewApp() *App {
    config := loadConfig()
    discord := NewDiscordService(&config)
    fileServer := &FileServer{FS: staticFS}
    gin.SetMode(gin.ReleaseMode)
    router := gin.New()
    router.Use(gin.Recovery())
    rateLimiter := NewRateLimiter(rate.Limit(config.RateLimit.Requests), config.RateLimit.PerSeconds)

    logFile, err := os.OpenFile("dccdn.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0775)
    if err != nil {
        log.Fatal("Failed to open log file:", err)
    }
    logger := log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

    return &App{
        Config:     config,
        Discord:    discord,
        FileServer: fileServer,
        Router:     router,
        RateLimiter: rateLimiter,
        Logger: logger,
    }
}

func loadConfig() Config {
    var config Config

    if err := godotenv.Load(); err != nil {
        log.Println("Warning: No .env file found")
    }

    token := os.Getenv("TOKEN")
    if token == "" {
        log.Fatal("TOKEN environment variable is required")
    }

    domain := os.Getenv("DOMAIN")
    if domain == "" {
        log.Fatal("DOMAIN environment variable is required")
    }

    filec := os.Getenv("FILEC")
    if filec == "" {
        log.Fatal("FILE CHANNEL environment variable is required")
    }

    cid := os.Getenv("CID")
    if cid == "" {
        log.Fatal("CID environment variable is required")
    }

    portStr := os.Getenv("PORT")
    if portStr == "" {
        portStr = "10000"
    }

    port, err := strconv.Atoi(portStr)
    if err != nil {
        log.Fatalf("Invalid port: %v", err)
    }

    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    if err := viper.ReadInConfig(); err != nil {
        log.Fatalf("Config error: %v", err)
    }
    if err := viper.Unmarshal(&config); err != nil {
        log.Fatalf("Config unmarshal error: %v", err)
    }

    config.Token = token
    config.Port = port
    config.Domain = domain
    config.FileChannel = filec
    config.ChannelID = cid
    config.Version = "0.0.5"

    return config
}

func NewDiscordService(config *Config) *DiscordService {
    session, err := discordgo.New("Bot " + config.Token)
    if err != nil {
        log.Fatal("Discord session error:", err)
    }
    return &DiscordService{
        Session: session,
        Config:  config,
    }
}

func (d *DiscordService) Open() error {
    d.Session.AddHandler(d.handleCommands)
    d.Session.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
        log.Println("Bot is ready! Connected as", r.User.Username)
        
        commands := []*discordgo.ApplicationCommand{
            {
                Name:        "healthcheck",
                Description: "Check the health status of the CDN service",
            },
            {
                Name:        "restart",
                Description: "Restart the CDN service",
            },
            {
                Name:        "about",
                Description: "Show information about this bot",
            },
            {
                Name:        "how",
                Description: "Show usage instructions",
            },
        }
        
        for _, cmd := range commands {
            _, err := d.Session.ApplicationCommandCreate(d.Session.State.User.ID, "", cmd)
            if err != nil {
                log.Printf("Cannot create '%v' command: %v", cmd.Name, err)
            }
        }
    })
    
    return d.Session.Open()
}

func (d *DiscordService) handleCommands(s *discordgo.Session, i *discordgo.InteractionCreate) {
    if i.Type != discordgo.InteractionApplicationCommand {
        return
    }
    
    switch i.ApplicationCommandData().Name {
    case "healthcheck":
        d.handleHealthCheck(s, i)
    case "restart":
        d.handleRestart(s, i)
    case "about":
        d.handleAbout(s, i)
    case "how":
        d.handleHow(s, i)
    }
}

func (d *DiscordService) handleAbout(s *discordgo.Session, i *discordgo.InteractionCreate) {
    embed := &discordgo.MessageEmbed{
        Title: "About DCCDN",
        Color: 0x00ff00,
        Fields: []*discordgo.MessageEmbedField{
            {Name: "Version", Value: d.Config.Version, Inline: true},
            {Name: "Author", Value: "Scz", Inline: true},
            {Name: "GitHub", Value: "https://github.com/Schutz3/dccdn", Inline: false},
        },
        Description: "Discord Custom CDN - Auto-refresh Discord URLs to prevent expiration",
        Footer: &discordgo.MessageEmbedFooter{
            Text: "Juan Gantenk",
        },
    }

    s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
        Type: discordgo.InteractionResponseChannelMessageWithSource,
        Data: &discordgo.InteractionResponseData{
            Embeds: []*discordgo.MessageEmbed{embed},
        },
    })
}

func (d *DiscordService) handleHow(s *discordgo.Session, i *discordgo.InteractionCreate) {
    embed := &discordgo.MessageEmbed{
        Title: "How to Use",
        Color: 0x00ff00,
        Description: "**Usage Instructions:**\n" +
            "1. Upload files using the web interface or ShareX\n" +
            "2. Use the generated URLs to access your files\n" +
            "3. URLs automatically refresh when accessed\n\n" +
            "**Features:**\n" +
            "• Multiple URL formats\n" +
            "• File previews\n" +
            "• Discord integration\n" +
            "• Rate limiting",
        Footer: &discordgo.MessageEmbedFooter{
            Text: "Juan Gantenk",
        },
    }

    s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
        Type: discordgo.InteractionResponseChannelMessageWithSource,
        Data: &discordgo.InteractionResponseData{
            Embeds: []*discordgo.MessageEmbed{embed},
        },
    })
}


func (d *DiscordService) handleHealthCheck(s *discordgo.Session, i *discordgo.InteractionCreate) {
    uptime := time.Since(startTime).String()
    
    embed := &discordgo.MessageEmbed{
        Title:       "Health Status",
        Description: "Current status of the CDN service",
        Color:       0x00ff00,
        Fields: []*discordgo.MessageEmbedField{
            {
                Name:   "Status",
                Value:  "Online",
                Inline: true,
            },
            {
                Name:   "Uptime",
                Value:  uptime,
                Inline: true,
            },
            {
                Name:   "Discord Connection",
                Value:  "Connected",
                Inline: true,
            },
            {
                Name:   "Version",
                Value:  d.Config.Version,
                Inline: true,
            },
        },
        Timestamp: time.Now().Format(time.RFC3339),
        Footer: &discordgo.MessageEmbedFooter{
            Text: "DCCDN Health Check",
        },
    }
    
    s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
        Type: discordgo.InteractionResponseChannelMessageWithSource,
        Data: &discordgo.InteractionResponseData{
            Embeds: []*discordgo.MessageEmbed{embed},
        },
    })
}

func (d *DiscordService) handleRestart(s *discordgo.Session, i *discordgo.InteractionCreate) {
    s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
        Type: discordgo.InteractionResponseChannelMessageWithSource,
        Data: &discordgo.InteractionResponseData{
            Content: "Restarting the CDN service...",
        },
    })
    
    if restartChan != nil {
        restartChan <- true
    }
}

func (d *DiscordService) Close() error {
    return d.Session.Close()
}

func (d *DiscordService) EditMessage(messageID, content string) error {
    _, err := d.Session.ChannelMessageEdit(d.Config.FileChannel, messageID, content)
    return err
}

func (d *DiscordService) GetMessage(messageId string) (*discordgo.Message, error) {
    return d.Session.ChannelMessage(d.Config.FileChannel, messageId)
}

func (d *DiscordService) SendFile(filename string, content io.Reader) (*discordgo.Message, error) {
    return d.Session.ChannelFileSend(d.Config.FileChannel, filename, content)
}

func (d *DiscordService) RefreshDiscordUrl(originalLink string) (string, error) {
    payload := map[string][]string{
        "attachment_urls": {originalLink},
    }

    jsonPayload, _ := json.Marshal(payload)

    req, _ := http.NewRequest("POST", "https://discord.com/api/v9/attachments/refresh-urls", bytes.NewBuffer(jsonPayload))
    req.Header.Set("Authorization", "Bot "+d.Config.Token)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return "", fmt.Errorf("Failed to refresh Discord URL")
    }

    var result map[string][]map[string]string
    json.NewDecoder(resp.Body).Decode(&result)

    return result["refreshed_urls"][0]["refreshed"], nil
}

func (rl *RateLimiter) Allow(ip string) bool {
    rl.mtx.Lock()
    limiter, exists := rl.visitors[ip]
    if !exists {
        limiter = rate.NewLimiter(rl.r, rl.b)
        rl.visitors[ip] = limiter
    }
    rl.mtx.Unlock()
    return limiter.Allow()
}

func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
    rl.mtx.Lock()
    defer rl.mtx.Unlock()
    
    limiter, exists := rl.visitors[ip]
    if !exists {
        limiter = rate.NewLimiter(rl.r, rl.b)
        rl.visitors[ip] = limiter
    }
    
    return limiter
}

func (a *App) RateLimitMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        if a.Config.RateLimit.Enabled {
            ip := c.ClientIP()
            if !a.RateLimiter.Allow(ip) {
                c.JSON(http.StatusTooManyRequests, gin.H{
                    "error": a.Config.RateLimit.Message,
                })
                c.Abort()
                return
            }
        }
        c.Next()
    }
}

func (a *App) AnalyticsMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        path := c.Request.URL.Path
        
        c.Next()
        
        latency := time.Since(start)
        clientIP := c.ClientIP()
        method := c.Request.Method
        statusCode := c.Writer.Status()
        userAgent := c.Request.UserAgent()
        
        logMessage := fmt.Sprintf("[ANALYTICS] %s | %3d | %13v | %15s | %s | %s",
            method, statusCode, latency, clientIP, path, userAgent)
        
        a.Logger.Println(logMessage)
        
        if a.Config.Analytics.Enabled && a.Config.Analytics.LogToDiscord && a.Config.ChannelID != "" {
            go func() {
                embed := &discordgo.MessageEmbed{
                    Title:       "CDN Analytics",
                    Description: fmt.Sprintf("```%s```", logMessage),
                    Color:       0x00ff00, 
                    Timestamp:   time.Now().Format(time.RFC3339),
                    Fields: []*discordgo.MessageEmbedField{
                        {Name: "Method", Value: method, Inline: true},
                        {Name: "Status", Value: strconv.Itoa(statusCode), Inline: true},
                        {Name: "Latency", Value: latency.String(), Inline: true},
                        {Name: "IP", Value: clientIP, Inline: true},
                        {Name: "Path", Value: path, Inline: true},
                        {Name: "User Agent", Value: userAgent, Inline: false},
                    },
                    Footer: &discordgo.MessageEmbedFooter{
                        Text: "DCCDN Analytics",
                    },
                }
                
                _, err := a.Discord.Session.ChannelMessageSendEmbed(a.Config.ChannelID, embed)
                if err != nil {
                    a.Logger.Printf("Failed to send analytics to channel: %v", err)
                }
            }()
        }
    }
}

func (e *FileServer) Open(name string) (http.File, error) {
    name = strings.TrimPrefix(name, "/")
    if name == "" {
        name = "index.html"
    }
    file, err := e.FS.Open("public/" + name)
    if err != nil {
        return nil, err
    }
    return &embeddedFileWrapper{file}, nil
}

func (e *FileServer) Exists(prefix string, path string) bool {
    path = strings.TrimPrefix(path, "/")
    _, err := e.FS.Open("public/" + path)
    return err == nil
}

type embeddedFileWrapper struct {
    fs.File
}

func (f *embeddedFileWrapper) Readdir(count int) ([]fs.FileInfo, error) {
    return nil, fmt.Errorf("Readdir is not supported")
}

func (f *embeddedFileWrapper) Seek(offset int64, whence int) (int64, error) {
    return 0, fmt.Errorf("Seek is not supported")
}

func NewFileHandler(discord *DiscordService, config *Config) *FileHandler {
    return &FileHandler{
        Discord: discord,
        Config:  config,
    }
}

func (a *App) SetupRoutes() {
    a.Router.Use(static.Serve("/", a.FileServer))
    tmpl := template.Must(template.ParseFS(templateFS, "views/*.html"))
    a.Router.SetHTMLTemplate(tmpl)
    handler := NewFileHandler(a.Discord, &a.Config)
    a.Router.GET("/about", handler.HandleAbout)
    a.Router.Use(a.AnalyticsMiddleware())
    a.Router.GET("/", handler.HandleIndex)
    a.Router.GET("/results", handler.HandleResults)
    a.Router.GET("/sharex", handler.HandleShareX)
    a.Router.GET("/:messageId", handler.HandleMessageId)
    a.Router.GET("/:messageId/:fname", handler.HandleMessageFname)
    a.Router.GET("/v1/:messageId", handler.HandleV1MessageId)
    a.Router.GET("/dl/:messageId", handler.HandleAttachments)
    a.Router.POST("/api/sharex", a.RateLimitMiddleware(), handler.HandleApiShareX)


    a.Router.GET("/health", a.RateLimitMiddleware(), func(c *gin.Context) {
        var discordStatus string
        if a.Discord.Session.State.User != nil {
            discordStatus = "ok"
        } else {
            discordStatus = "error"
        }
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        cpuUsage := getCPUUsage()
        numCPU := runtime.NumCPU()
        totalMem, freeMem := getMemoryInfo()
        diskTotal, diskFree, diskUsed := getDiskInfo()
        bytesIn, bytesOut := getNetworkStats()
        rateLimit := a.Config.RateLimit
        c.JSON(http.StatusOK, gin.H{
            "status":        "ok",
            "uptime":        time.Since(startTime).String(),
            "discord":       discordStatus,
            "version":       a.Config.Version,
            "go_version":    runtime.Version(),
            "os":            runtime.GOOS,
            "arch":          runtime.GOARCH,
            "rate_limit":    rateLimit,
            "sysinfo": gin.H{
                "cpu": gin.H{
                    "usage":     fmt.Sprintf("%.2f%%", cpuUsage),
                    "cores":     numCPU,
                },
                "memory": gin.H{
                    "total":     formatBytes(totalMem),
                    "used":      formatBytes(totalMem - freeMem),
                    "free":      formatBytes(freeMem),
                    "go_alloc":  formatBytes(int64(m.Alloc)),
                    "go_total":  formatBytes(int64(m.TotalAlloc)),
                    "go_sys":    formatBytes(int64(m.Sys)),
                },
                "disk": gin.H{
                    "total":     formatBytes(diskTotal),
                    "used":      formatBytes(diskUsed),
                    "free":      formatBytes(diskFree),
                },
                "network": gin.H{
                    "in":  formatBytes(bytesIn),
                    "out": formatBytes(bytesOut),
                },
            },
            
        })
    })
}

func (a *App) Run() error {
    if err := a.Discord.Open(); err != nil {
        return fmt.Errorf("Discord connection error: %w", err)
    }
    defer a.Discord.Close()

    log.Printf("Server running on %s:%d", a.Config.Host, a.Config.Port)
    return a.Router.Run(fmt.Sprintf("%s:%d", a.Config.Host, a.Config.Port))
}

func (h *FileHandler) HandleIndex(c *gin.Context) {
    maxFileSize := h.Config.MaxFileSize.Byte
    humanFileSize := h.Config.MaxFileSize.Human

    c.HTML(http.StatusOK, "index.html", gin.H{
        "MaxFileSize":   maxFileSize,
        "humanFileSize": humanFileSize,
    })
}

func (h *FileHandler) HandleAbout(c *gin.Context) {
    c.HTML(http.StatusOK, "about.html", gin.H{
        "Version":   h.Config.Version,
        "GoVersion": runtime.Version(),
    })
}

func (h *FileHandler) HandleResults(c *gin.Context) {
    uploadResults, err := c.Cookie("results")
    if err != nil {
        c.Redirect(http.StatusFound, "/")
        return
    }

    var results map[string]string
    if err := json.Unmarshal([]byte(uploadResults), &results); err != nil {
        c.Redirect(http.StatusFound, "/")
        return
    }

    c.HTML(http.StatusOK, "results.html", gin.H{
        "URL":        results["cdn"],
        "ProxyURL":   results["proxy"],
        "CustomURL":  results["custom"],
        "MessageID":  results["id"],
        "UploadDate": results["uploaded"],
        "FileType":   results["mime"],
        "CustomURL2": fmt.Sprintf("https://%s/v1/%s", h.Config.Domain, results["id"]),
        "CustomURL3": fmt.Sprintf("https://%s/%s/%s", h.Config.Domain, results["id"], results["fname"]),
        "FileName":  results["fname"],
    })
}

func (h *FileHandler) HandleShareX(c *gin.Context) {
    uploadResults, _ := c.Cookie("results")
    var results map[string]interface{}
    json.Unmarshal([]byte(uploadResults), &results)
    c.String(http.StatusOK, results["custom"].(string))
}

func (h *FileHandler) HandleMessageId(c *gin.Context) {
    messageId := c.Param("messageId")

    if _, err := strconv.ParseInt(messageId, 10, 64); err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Invalid message ID"})
        return
    }

    message, err := h.Discord.GetMessage(messageId)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
        return
    }

    cdnUrl, _ := h.Discord.RefreshDiscordUrl(message.Attachments[0].URL)
    proxyUrl, _ := h.Discord.RefreshDiscordUrl(message.Attachments[0].ProxyURL)
    fname := message.Attachments[0].Filename

    c.HTML(http.StatusOK, "results.html", gin.H{
        "URL":        cdnUrl,
        "ProxyURL":   proxyUrl,
        "CustomURL":  fmt.Sprintf("https://%s/dl/%s", h.Config.Domain, message.ID),
        "MessageID":  message.ID,
        "UploadDate": time.Now().Format("File uploaded on January 2, 2006 PST"),
        "FileType":   message.Attachments[0].ContentType,
        "CustomURL2": fmt.Sprintf("https://%s/v1/%s", h.Config.Domain, message.ID),
        "FileName":   message.Attachments[0].Filename,
        "CustomURL3": fmt.Sprintf("https://%s/%s/%s", h.Config.Domain, message.ID, fname),
    })
}

func (h *FileHandler) HandleMessageFname(c *gin.Context) {
    messageId := c.Param("messageId")
    fname := c.Param("fname")

    if _, err := strconv.ParseInt(messageId, 10, 64); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message ID format"})
        return
    }

    message, err := h.Discord.GetMessage(messageId)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
        return
    }

    if fname != "" && message.Attachments[0].Filename != fname {
        c.JSON(http.StatusNotFound, gin.H{"error": "File name not found / not match"})
        return
    }

    if len(message.Attachments) == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "No attachments in message"})
        return
    }

    attachment := message.Attachments[0]

    cdnUrl, err := h.Discord.RefreshDiscordUrl(attachment.URL)
    if err != nil {
        log.Printf("CDN refresh failed: %v", err)
        c.JSON(http.StatusFailedDependency, gin.H{"error": "Failed to refresh file URL"})
        return
    }

    resp, err := http.Get(cdnUrl)
    if err != nil {
        c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to retrieve file"})
        return
    }
    defer resp.Body.Close()

    contentType := resp.Header.Get("Content-Type")
    if contentType == "application/pdf" {
        c.Header("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, attachment.Filename))
    } else {
        c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, attachment.Filename))
    }
    c.Header("Content-Type", contentType)

    _, err = io.Copy(c.Writer, resp.Body)
    if err != nil {
        log.Printf("Stream error: %v", err)
    }
}

func (h *FileHandler) HandleV1MessageId(c *gin.Context) {
    messageId := c.Param("messageId")

    message, err := h.Discord.GetMessage(messageId)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
        return
    }

    cdnUrl, err := h.Discord.RefreshDiscordUrl(message.Attachments[0].URL)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "CDN URL not found"})
        return
    }

    resp, err := http.Get(cdnUrl)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
        return
    }
    defer resp.Body.Close()

    c.DataFromReader(http.StatusOK, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
}

func (h *FileHandler) HandleAttachments(c *gin.Context) {
    messageId := c.Param("messageId")
    
    if _, err := strconv.ParseInt(messageId, 10, 64); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message ID format"})
        return
    }

    message, err := h.Discord.GetMessage(messageId)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
        return
    }

    if len(message.Attachments) == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "No attachments in message"})
        return
    }

    attachment := message.Attachments[0]
    
    cdnUrl, err := h.Discord.RefreshDiscordUrl(attachment.URL)
    if err != nil {
        log.Printf("CDN refresh failed: %v", err)
        c.JSON(http.StatusFailedDependency, gin.H{"error": "Failed to refresh file URL"})
        return
    }

    resp, err := http.Get(cdnUrl)
    if err != nil {
        c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to retrieve file"})
        return
    }
    defer resp.Body.Close()

    c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, attachment.Filename))
    c.Header("Content-Type", resp.Header.Get("Content-Type"))
    
    _, err = io.Copy(c.Writer, resp.Body)
    if err != nil {
        log.Printf("Stream error: %v", err)
    }
}

func (h *FileHandler) HandleApiShareX(c *gin.Context) {
    if mid := c.PostForm("mid"); mid != "" {
        message, err := h.Discord.GetMessage(mid)
        if err != nil {
            c.String(http.StatusNotFound, "Message not found.")
            return
        }
        h.SetCookies(c, message)
        c.Redirect(http.StatusFound, "/sharex")
        return
    }

    file, header, err := c.Request.FormFile("file")
    if err != nil {
        c.String(http.StatusBadRequest, fmt.Sprintf("Error: %s", err.Error()))
        return
    }
    defer file.Close()

    if header.Size > h.Config.MaxFileSize.Byte {
        c.String(http.StatusRequestEntityTooLarge, "File too large.")
        return
    }

    reader := &progressReader{
        reader:   file,
        size:     header.Size,
        progress: make(chan int64, 100),
    }

    go func() {
        lastPercent := int64(-1)
        for p := range reader.progress {
            percent := int64(float64(p) / float64(reader.size) * 100)
            if percent != lastPercent {
                lastPercent = int64(percent)
            }
        }
    }()

    buffer := bytes.NewBuffer(nil)
    if _, err := io.Copy(buffer, reader); err != nil {
        log.Printf("Error while copying file: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": true, "message": fmt.Sprintf("Error while processing file: %v", err)})
        return
    }

    msg, err := h.Discord.SendFile(header.Filename, buffer)
    if err != nil {
        log.Printf("Error while sending file: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": true, "message": fmt.Sprintf("Error while processing file: %v", err)})
        return
    }

    fname := msg.Attachments[0].Filename

    content := fmt.Sprintf("``File details:`` ``https://%s/%s``\n``Custom URL #1:`` ```https://%s/v1/%s``` ``Custom URL #2:`` ```https://%s/dl/%s``` ``Custom URL #3:`` ```https://%s/%s/%s```",
        h.Config.Domain, msg.ID,
        h.Config.Domain, msg.ID,
        h.Config.Domain, msg.ID,
        h.Config.Domain, msg.ID, fname)

    if err := h.Discord.EditMessage(msg.ID, content); err != nil {
        log.Printf("Failed to edit message: %v", err)
    }

    h.SetCookies(c, msg)

    if c.GetHeader("Upload-Source") == "API" {
        c.Redirect(http.StatusFound, "/sharex")
    } else {
        c.JSON(http.StatusOK, gin.H{"status": "success"})
    }
}

func (r *progressReader) Read(p []byte) (int, error) {
    n, err := r.reader.Read(p)
    if n > 0 {
        r.read += int64(n)
        if r.progress != nil {
            r.progress <- r.read
        }
    }
    return n, err
}

func (h *FileHandler) SetCookies(c *gin.Context, message *discordgo.Message) {
    cdnUrl, _ := h.Discord.RefreshDiscordUrl(message.Attachments[0].URL)
    proxyUrl, _ := h.Discord.RefreshDiscordUrl(message.Attachments[0].ProxyURL)

    cookieData := gin.H{
        "cdn":      cdnUrl,
        "proxy":    proxyUrl,
        "custom":   fmt.Sprintf("https://%s/dl/%s", h.Config.Domain, message.ID),
        "id":       message.ID,
        "uploaded": time.Now().Format("File uploaded on January 2, 2006 PST"),
        "mime":     message.Attachments[0].ContentType,
        "fname": message.Attachments[0].Filename,
    }

    jsonData, _ := json.Marshal(cookieData)
    c.SetCookie(
        "results",
        string(jsonData),
        900,
        "/",
        "",
        false,
        false,
    )
}

func HumanizeBytes(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatBytes(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Get CPU usage percentage
func getCPUUsage() float64 {
    percentages, err := cpu.Percent(0, false)
    if err != nil {
        return 0.0
    }
    if len(percentages) > 0 {
        return percentages[0]
    }
    return 0.0
}

// Get memory information
func getMemoryInfo() (int64, int64) {
    vmStat, err := mem.VirtualMemory()
    if err != nil {
        return 0, 0
    }
    return int64(vmStat.Total), int64(vmStat.Free)
}

// Get disk information
func getDiskInfo() (int64, int64, int64) {
    diskStat, err := disk.Usage("/")
    if err != nil {
        return 0, 0, 0
    }
    return int64(diskStat.Total), int64(diskStat.Free), int64(diskStat.Used)
}

// Get network statistics
func getNetworkStats() (int64, int64) {
    netStats, err := net.IOCounters(false)
    if err != nil || len(netStats) == 0 {
        return 0, 0
    }
    
    var bytesRecv, bytesSent int64
    for _, stat := range netStats {
        bytesRecv += int64(stat.BytesRecv)
        bytesSent += int64(stat.BytesSent)
    }
    
    return bytesRecv, bytesSent
}

func main() {
    startTime = time.Now()
    restartChan = make(chan bool, 1)
    
    for {
        app := NewApp()
        app.SetupRoutes()
        
        quit := make(chan os.Signal, 1)
        signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
        
        server := &http.Server{
            Addr:    fmt.Sprintf("%s:%d", app.Config.Host, app.Config.Port),
            Handler: app.Router,
        }
        
        go func() {
            app.Logger.Printf("Server running on %s:%d", app.Config.Host, app.Config.Port)
            if err := app.Discord.Open(); err != nil {
                app.Logger.Fatalf("Discord connection error: %v", err)
            }
            
            if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                app.Logger.Fatalf("Server failed: %v", err)
            }
        }()
        
        select {
        case <-quit:
            app.Logger.Println("Shutting down server...")
            
            ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
            defer cancel()
            
            if err := server.Shutdown(ctx); err != nil {
                app.Logger.Fatalf("Server forced to shutdown: %v", err)
            }
            
            if err := app.Discord.Close(); err != nil {
                app.Logger.Printf("Error closing Discord connection: %v", err)
            }
            
            app.Logger.Println("Server exited gracefully")
            return
            
        case <-restartChan:
            app.Logger.Println("Restarting server...")
            
            ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
            
            if err := server.Shutdown(ctx); err != nil {
                app.Logger.Printf("Server shutdown error during restart: %v", err)
            }
            
            if err := app.Discord.Close(); err != nil {
                app.Logger.Printf("Error closing Discord connection during restart: %v", err)
            }
            
            cancel()
            app.Logger.Println("Server restarted")
            startTime = time.Now() 
            continue
        }
    }
}