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
var (
    config Config
    dg     *discordgo.Session
)
type embeddedStatic struct {
    fs embed.FS
}
type embeddedFile struct {
    fs.File
}
type progressReader struct {
    reader   io.Reader
    size     int64
    progress chan int64 
    read     int64
}

func (f embeddedFile) Readdir(count int) ([]fs.FileInfo, error) {
    return nil, fmt.Errorf("Readdir is not supported")
}


func (e *embeddedStatic) Open(name string) (http.File, error) {
    name = strings.TrimPrefix(name, "/")
    if name == "" {
        name = "index.html"
    }
    file, err := e.fs.Open("public/" + name)
    if err != nil {
        return nil, err
    }
    return &embeddedFileWrapper{file}, nil
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

func (e *embeddedStatic) Exists(prefix string, path string) bool {
    path = strings.TrimPrefix(path, "/")
    _, err := e.fs.Open("public/" + path)
    return err == nil
}

func init() {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    if err := viper.ReadInConfig(); err != nil {
        log.Fatal("Config error:", err)
    }
    if err := viper.Unmarshal(&config); err != nil {
        log.Fatal("Config unmarshal error:", err)
    }

    var err error
    dg, err = discordgo.New("Bot " + config.Token)
    if err != nil {
        log.Fatal("Discord session error:", err)
    }
}

func main() {
    gin.SetMode(gin.ReleaseMode)
    r := gin.New()
    r.Use(gin.Recovery())

    r.Use(static.Serve("/", &embeddedStatic{fs: staticFS}))
    
    tmpl := template.Must(template.ParseFS(templateFS, "views/*.html"))
    r.SetHTMLTemplate(tmpl)

    r.GET("/", handleIndex)
    r.GET("/results", handleResults)
    r.GET("/sharex", handleShareX)
    r.GET("/:messageId", handleMessageId)
    r.GET("/v1/:messageId", handleV1MessageId)
    r.GET("/dl/:messageId", handleAttachments)
    r.POST("/api/sharex", handleApiShareX)

    if err := dg.Open(); err != nil {
        log.Fatal("Discord connection error:", err)
    }
    defer dg.Close()

    log.Printf("Server running on %s:%d", config.Host, config.Port)
    if err := r.Run(fmt.Sprintf("%s:%d", config.Host, config.Port)); err != nil {
        log.Fatal("Server failed:", err)
    }
}

func handleIndex(c *gin.Context) {
    maxFileSize := config.MaxFileSize.Byte
    humanFileSize := config.MaxFileSize.Human

    c.HTML(http.StatusOK, "index.html", gin.H{
        "MaxFileSize":   maxFileSize,
        "humanFileSize": humanFileSize,
    })
}

func humanizeBytes(bytes int64) string {
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

func handleResults(c *gin.Context) {
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
        "CustomURL2": fmt.Sprintf("https://%s/v1/%s", config.Domain, results["id"]),
    })
}

func handleShareX(c *gin.Context) {
    uploadResults, _ := c.Cookie("results")
    var results map[string]interface{}
    json.Unmarshal([]byte(uploadResults), &results)
    c.String(http.StatusOK, results["custom"].(string))
}

func handleMessageId(c *gin.Context) {
    messageId := c.Param("messageId")

    if _, err := strconv.ParseInt(messageId, 10, 64); err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Invalid message ID"})
        return
    }

    message, err := dg.ChannelMessage(config.FileChannel, messageId)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
        return
    }

    cdnUrl, _ := getRefreshedDiscordUrl(message.Attachments[0].URL)
    proxyUrl, _ := getRefreshedDiscordUrl(message.Attachments[0].ProxyURL)

    uploadResults := gin.H{
        "cdn":      cdnUrl,
        "proxy":    proxyUrl,
        "custom":   fmt.Sprintf("https://%s/dl/%s", config.Domain, message.ID),
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
        "customURL2": fmt.Sprintf("https://%s/v1/%s", config.Domain, uploadResults["id"]),
    })
}

func handleV1MessageId(c *gin.Context) {
    messageId := c.Param("messageId")

    message, err := dg.ChannelMessage(config.FileChannel, messageId)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
        return
    }

    cdnUrl, err := getRefreshedDiscordUrl(message.Attachments[0].URL)
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

func handleAttachments(c *gin.Context) {
    messageId := c.Param("messageId")
    
    if _, err := strconv.ParseInt(messageId, 10, 64); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message ID format"})
        return
    }

    message, err := dg.ChannelMessage(config.FileChannel, messageId)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
        return
    }

    if len(message.Attachments) == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "No attachments in message"})
        return
    }

    attachment := message.Attachments[0]
    
    cdnUrl, err := getRefreshedDiscordUrl(attachment.URL)
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

func handleApiShareX(c *gin.Context) {
	if mid := c.PostForm("mid"); mid != "" {
		message, err := dg.ChannelMessage(config.FileChannel, mid)
		if err != nil {
			c.String(http.StatusNotFound, "Message not found.")
			return
		}
		setCookies(c, message)
		c.Redirect(http.StatusFound, "/sharex")
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("Error: %s", err.Error()))
		return
	}
	defer file.Close()

	if header.Size > config.MaxFileSize.Byte {
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
        c.JSON(http.StatusInternalServerError, gin.H{ "error": true, "message": fmt.Sprintf("Error while processing file: %v", err) })
        return
    }

	msg, err := dg.ChannelFileSend(config.FileChannel, header.Filename, buffer)
	if err != nil {
        log.Printf("Error while sending file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{ "error": true, "message": fmt.Sprintf("Error while processing file: %v", err) })
		return
	}

	setCookies(c, msg)

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

func setCookies(c *gin.Context, message *discordgo.Message) {
    cdnUrl, _ := getRefreshedDiscordUrl(message.Attachments[0].URL)
    proxyUrl, _ := getRefreshedDiscordUrl(message.Attachments[0].ProxyURL)

    cookieData := gin.H{
        "cdn":      cdnUrl,
        "proxy":    proxyUrl,
        "custom":   fmt.Sprintf("https://%s/dl/%s", config.Domain, message.ID),
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

func getRefreshedDiscordUrl(originalLink string) (string, error) {
    payload := map[string][]string{
        "attachment_urls": {originalLink},
    }

    jsonPayload, _ := json.Marshal(payload)

    req, _ := http.NewRequest("POST", "https://discord.com/api/v9/attachments/refresh-urls", bytes.NewBuffer(jsonPayload))
    req.Header.Set("Authorization", "Bot "+config.Token)
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