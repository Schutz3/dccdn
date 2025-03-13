![DCCDN UPTIME & STATUS](https://cdn.scz.my.id/health)


# DCCDN
A simple website that allows you to upload files to Discord's CDN without having to do it in their app.

## Prerequisites
Golang (to build from stratch)
[Discord Bot](https://discord.com/developers/applications)
[Git](https://git-scm.com/downloads)

## Installation
### Run this command:
```
git clone git@github.com:Schutz3/dccdn.git
```
or download the ZIP file and extract it
```
cd dccdn
```
### Follow these steps:
- Rename [examle.config.yaml](examle.config.yaml) to `config.yaml`
- Go to https://discord.com/developers/applications and create bot
- Make sure this is enabled
![Message Content Intent](https://cdn.scz.my.id/dl/1349628111032946751 "Message Content Intent")
- Invite the bot to your server using this link: `https://discord.com/api/oauth2/authorize?client_id=INSERT YOUR APPLICATION ID&permissions=8&scope=bot`
- Configure the `config.yaml` file 

### Continue with running these commands:
```
go get
```
```
go run main.go
```

## Usage
The website will be up @ http://localhost:8080 (unless you've changed the config)

Files uploaded on the site will be available in the channel that you set in `config.yaml`

## Usage with ShareX
DCCDN can also be used with [ShareX](https://getsharex.com/)! Follow these steps to get it working (don't want to follow steps? [click here to download the backup (using my instance)](https://cdn.scz.my.id/dl/1349629296360296469)):

1. Copy the upload endpoint. If using localhost it will be `http://localhost:8080/api/sharex`, or if you're using my instance it will be `https://cdn.scz.my.id/api/sharex`
2. Open ShareX and go to `Destinations` > `Custom uploader settings` > Click `New`
3. Name it whatever you want & paste the upload endpoint in `Request URL`
4. Under `Destination type`, select `Image uploader`, `Text uploader`, and `File uploader`
5. Body should be `Form data (multipart/form-data)` and `File form name` should just be `file`.
6. In the HEADERS section, set the name to `Upload-Source` and the value to `API`
7. Select your new ShareX config in the dropdowns at the bottom left of your screen
8. Have fun with your new DCCDN.