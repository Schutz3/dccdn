package main

import (
    "bytes"
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

    "github.com/bwmarrin/discordgo"
    "github.com/gin-contrib/static"
    "github.com/gin-gonic/gin"
    "github.com/spf13/viper"
)

//go:embed views/*.html
var templateFS embed.FS
//go:embed public
var staticFS embed.FS

type Config struct {
    Port        int    `mapstructure:"port"`
    Host        string `mapstructure:"host"`
    Domain      string `mapstructure:"domain"`
    Token       string `mapstructure:"token"`
    FileChannel string `mapstructure:"fileChannel"`
    MaxFileSize struct {
        Human string `mapstructure:"human"`
        Byte  int64  `mapstructure:"byte"`
    } `mapstructure:"maxFileSize"`
}

type App struct {
    Config     Config
    Discord    *DiscordService
    FileServer *FileServer
    Router     *gin.Engine
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

func NewApp() *App {
    config := loadConfig()
    discord := NewDiscordService(&config)
    fileServer := &FileServer{FS: staticFS}
    gin.SetMode(gin.ReleaseMode)
    router := gin.New()
    router.Use(gin.Recovery())

    return &App{
        Config:     config,
        Discord:    discord,
        FileServer: fileServer,
        Router:     router,
    }
}

func loadConfig() Config {
    var config Config
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    if err := viper.ReadInConfig(); err != nil {
        log.Fatal("Config error:", err)
    }
    if err := viper.Unmarshal(&config); err != nil {
        log.Fatal("Config unmarshal error:", err)
    }
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
    return d.Session.Open()
}

func (d *DiscordService) Close() error {
    return d.Session.Close()
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

    a.Router.GET("/", handler.HandleIndex)
    a.Router.GET("/results", handler.HandleResults)
    a.Router.GET("/sharex", handler.HandleShareX)
    a.Router.GET("/:messageId", handler.HandleMessageId)
    a.Router.GET("/v1/:messageId", handler.HandleV1MessageId)
    a.Router.GET("/dl/:messageId", handler.HandleAttachments)
    a.Router.POST("/api/sharex", handler.HandleApiShareX)
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

    uploadResults := gin.H{
        "cdn":      cdnUrl,
        "proxy":    proxyUrl,
        "custom":   fmt.Sprintf("https://%s/dl/%s", h.Config.Domain, message.ID),
        "id":       message.ID,
        "uploaded": time.Now().Format("File uploaded on January 2, 2006 PST"),
        "mime":     message.Attachments[0].ContentType,
    }

    c.HTML(http.StatusOK, "results.html", gin.H{
        "url":        uploadResults["cdn"],
        "proxyURL":   uploadResults["proxy"],
        "customURL":  uploadResults["custom"],
        "messageId":  uploadResults["id"],
        "uploadDate": uploadResults["uploaded"],
        "fileType":   uploadResults["mime"],
        "customURL2": fmt.Sprintf("https://%s/v1/%s", h.Config.Domain, uploadResults["id"]),
    })
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

func main() {
    app := NewApp()
    app.SetupRoutes()
    
    if err := app.Run(); err != nil {
        log.Fatal("Server failed:", err)
    }
}