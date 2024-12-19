package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("my_secret_key")
var logger = logrus.New()
var adminPasswordHash []byte
var db *sql.DB
var rules []struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
}

const (
	subscriptionFile = "subscriptions.json"
	rulesFile        = "rules.json"
)

// 添加当前节点的全局变量
// var currentNode *Node

func init() {
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logger.SetLevel(logrus.InfoLevel)
	// 初始化默认密码
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	adminPasswordHash = hash

	// 确保必要的目录存在
	ensureDirectories()

	// 加载订阅和规则
	if err := loadSubscriptions(); err != nil {
		logger.Error("Failed to load subscriptions: " + err.Error())
	}
	if err := loadRules(); err != nil {
		logger.Error("Failed to load rules: " + err.Error())
	}

	// 初始化数据库
	if err := initDB(); err != nil {
		logger.Fatal("Failed to initialize database: " + err.Error())
	}
}

// 添加确保目录存在的函数
func ensureDirectories() {
	dirs := []string{
		"core",
		"panel",
		"config",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Error("Failed to create directory " + dir + ": " + err.Error())
		}
	}
}

func configureNetwork() {
	logger.Print("Configuring network...")
	time.Sleep(2 * time.Second)
	logger.Print("Network configured.")
}

func manageSingbox() {
	logger.Print("Managing Singbox...")
	time.Sleep(2 * time.Second)
	logger.Print("Singbox managed.")
}

func manageMosdns() {
	logger.Print("Managing Mosdns...")
	time.Sleep(2 * time.Second)
	logger.Print("Mosdns managed.")
}

func groupNodes() {
	logger.Print("Grouping nodes...")
	time.Sleep(2 * time.Second)
	logger.Print("Nodes grouped.")
}

func testNodeSpeed() {
	logger.Print("Testing node speed...")
	time.Sleep(2 * time.Second)
	logger.Print("Node speed tested.")
}

func updateRules() {
	logger.Print("Updating rules...")
	time.Sleep(2 * time.Second)
	logger.Print("Rules updated.")
}

func toggleAdBlock(enable bool) {
	if enable {
		logger.Print("AdBlock enabled.")
	} else {
		logger.Print("AdBlock disabled.")
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	username, password := r.FormValue("username"), r.FormValue("password")
	if username == "admin" && bcrypt.CompareHashAndPassword(adminPasswordHash, []byte(password)) == nil {
		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Subject:   username,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
		fmt.Fprintf(w, "{\"status\": \"logged in\"}")
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		tokenStr := cookie.Value
		claims := &jwt.StandardClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func viewLogs(w http.ResponseWriter, r *http.Request) {
	logger.Print("Viewing logs...")
	fmt.Fprintf(w, "{\"logs\": \"Sample log content\"}")
}

func backupConfig() {
	logger.Print("Backing up configuration...")
	time.Sleep(2 * time.Second)
	logger.Print("Configuration backed up.")
}

func restoreConfig() {
	logger.Print("Restoring configuration...")
	time.Sleep(2 * time.Second)
	logger.Print("Configuration restored.")
}

func getNodes(w http.ResponseWriter, _ *http.Request) {
	rows, err := db.Query("SELECT id, type, config, source FROM nodes")
	if err != nil {
		logger.Error("Error querying nodes: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var node Node
		if err := rows.Scan(&node.ID, &node.Type, &node.Config, &node.Source); err != nil {
			logger.Error("Error scanning node: " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		nodes = append(nodes, node)
	}

	if err := json.NewEncoder(w).Encode(nodes); err != nil {
		logger.Error("Error encoding nodes: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func addNode(w http.ResponseWriter, r *http.Request) {
	var node struct {
		Type   string `json:"type"`
		Config string `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		logger.Error("Error decoding node: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT INTO nodes (type, config) VALUES (?, ?)", node.Type, node.Config)
	if err != nil {
		logger.Error("Error inserting node: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "{\"status\": \"node added\"}")
}

func deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	_, err := db.Exec("DELETE FROM nodes WHERE id = ?", id)
	if err != nil {
		logger.Error("Error deleting node: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "{\"status\": \"node deleted\"}")
}

func manageNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		getNodes(w, r)
	case "POST":
		addNode(w, r)
	case "DELETE":
		deleteNode(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func manageRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		logger.Print("Fetching rules...")
		fmt.Fprintf(w, "{\"rules\": [{\"type\": \"custom\"}, {\"type\": \"remote\"}]}")
	case "POST":
		logger.Print("Adding rule...")
		fmt.Fprintf(w, "{\"status\": \"rule added\"}")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func manageSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		logger.Print("Fetching settings...")
		fmt.Fprintf(w, "{\"settings\": {\"ddns\": \"enabled\", \"proxy\": \"0.0.0.0:8080\"}}")
	case "POST":
		logger.Print("Updating settings...")
		fmt.Fprintf(w, "{\"status\": \"settings updated\"}")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func detailedLogs(w http.ResponseWriter, r *http.Request) {
	logger.Print("Fetching detailed logs...")
	fmt.Fprintf(w, "{\"logs\": \"Detailed log content with timestamps and levels\"}")
}

func enhancedBackup() {
	logger.Print("Performing enhanced backup...")
	time.Sleep(2 * time.Second)
	logger.Print("Enhanced backup completed.")
}

func downloadFile(url string, filepath string) error {
	out, err := os.Create(filepath)
	if err != nil {
		logger.Error("创建文件时出错: " + err.Error())
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		logger.Error("下载文件时出错: " + err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("下载失败，状态码: " + fmt.Sprint(resp.StatusCode))
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		logger.Error("写入文件时出错: " + err.Error())
	}
	return err
}

func extractTarGz(src, dest string, isCore bool) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	// 如果是核心文件，我们只保留可执行文件
	if isCore {
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			// 只处理文件（不处理目录）
			if !header.FileInfo().IsDir() {
				// 检查是否是可执行文件
				if strings.HasSuffix(header.Name, "sing-box") || strings.HasSuffix(header.Name, "mosdns") {
					// 直接保存到目标目录
					file, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
					if err != nil {
						return err
					}
					defer file.Close()

					if _, err := io.Copy(file, tr); err != nil {
						return err
					}
					break // 找到并复制了可执行文件后就退出
				}
			}
		}
		return nil
	}

	// 对于非核心文件（前端文件），保持原有的解压逻辑
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// 去掉第一层目录
		name := header.Name
		parts := strings.SplitN(name, "/", 2)
		if len(parts) > 1 {
			name = parts[1]
		}

		path := filepath.Join(dest, name)
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(file, tr)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractZip(src, dest string, isCore bool) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	// 如果是核心文件，我们只保留可执行文件
	if isCore {
		for _, f := range r.File {
			// 检查是否是可执行文件
			if strings.HasSuffix(f.Name, "mosdns") || strings.HasSuffix(f.Name, "sing-box") {
				rc, err := f.Open()
				if err != nil {
					return err
				}

				// 直接保存到目标目录
				outFile, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
				if err != nil {
					rc.Close()
					return err
				}

				_, err = io.Copy(outFile, rc)
				outFile.Close()
				rc.Close()
				if err != nil {
					return err
				}
				break // 找到并复制了可执行文件后就退出
			}
		}
		return nil
	}

	// 对于非核心文件（前端文件），去掉第一层目录
	for _, f := range r.File {
		// 去掉第一层目录
		name := f.Name
		parts := strings.SplitN(name, "/", 2)
		if len(parts) > 1 {
			name = parts[1]
		}

		fpath := filepath.Join(dest, name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTarXz(src, dest string) error {
	// 创建临时目录
	tempDir := dest + "_temp"
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	// 使用系统的tar命令来解压tar.xz文件到临时目录
	cmd := exec.Command("tar", "-xf", src, "-C", tempDir)
	if err := cmd.Run(); err != nil {
		return err
	}

	// 确保目标目录存在
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}

	// 移动文件
	files, err := os.ReadDir(tempDir)
	if err != nil {
		return err
	}

	// 如果解压后只有一个目录（如public），则移动其内容
	if len(files) == 1 && files[0].IsDir() {
		srcPath := filepath.Join(tempDir, files[0].Name())
		// 移动目录内容而不是目录本身
		subFiles, err := os.ReadDir(srcPath)
		if err != nil {
			return err
		}
		for _, subFile := range subFiles {
			oldPath := filepath.Join(srcPath, subFile.Name())
			newPath := filepath.Join(dest, subFile.Name())
			// 如果目标文件已存在，先删除
			if _, err := os.Stat(newPath); err == nil {
				if err := os.RemoveAll(newPath); err != nil {
					return err
				}
			}
			if err := os.Rename(oldPath, newPath); err != nil {
				return err
			}
		}
	} else {
		// 否则直接移动所有文件
		for _, file := range files {
			oldPath := filepath.Join(tempDir, file.Name())
			newPath := filepath.Join(dest, file.Name())
			// 如果目标文件已存在，先删除
			if _, err := os.Stat(newPath); err == nil {
				if err := os.RemoveAll(newPath); err != nil {
					return err
				}
			}
			if err := os.Rename(oldPath, newPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func downloadAndExtract(url, dest, format string, isCore bool) error {
	tempFile := "temp_download"
	err := downloadFile(url, tempFile)
	if err != nil {
		return err
	}
	defer os.Remove(tempFile)

	switch format {
	case "zip":
		return extractZip(tempFile, dest, isCore)
	case "tar.gz", "tgz":
		return extractTarGz(tempFile, dest, isCore)
	case "tar.xz":
		return extractTarXz(tempFile, dest)
	default:
		return errors.New("unsupported format: " + format)
	}
}

func downloadAndExtractFromGitHub(owner, repo, dest, format string) error {
	// 获取系统信息（仅用于后端程序）
	osType := runtime.GOOS
	arch := runtime.GOARCH

	// 构造API URL
	url := "https://api.github.com/repos/" + owner + "/" + repo + "/releases/latest"

	// 设置请求头，避免GitHub API限制
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "singdns")

	// 获取release数据
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("error fetching release data: " + err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to fetch release data: status code " + fmt.Sprint(resp.StatusCode))
	}

	// 解析JSON响应
	var release struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
		TagName string `json:"tag_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		logger.Error("error decoding release data: " + err.Error())
		return err
	}

	// 打印所有可用的资产
	logger.Print("Available assets for " + repo + " " + release.TagName + ":")
	for _, asset := range release.Assets {
		logger.Print("- " + asset.Name)
	}

	// 根据不同的仓库选择合适的下载文件
	var downloadURL string
	var errorMsg string
	var isCore bool

	switch repo {
	case "sing-box":
		isCore = true
		assetPattern := osType + "-" + arch
		for _, asset := range release.Assets {
			if strings.Contains(asset.Name, assetPattern) && strings.HasSuffix(asset.Name, ".tar.gz") && !strings.Contains(asset.Name, "legacy") {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
		errorMsg = "no suitable asset found for sing-box on " + osType + "-" + arch
	case "mosdns":
		isCore = true
		assetPattern := osType + "-" + arch
		for _, asset := range release.Assets {
			if strings.Contains(asset.Name, assetPattern) {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
		errorMsg = "no suitable asset found for mosdns on " + osType + "-" + arch
	case "yacd":
		isCore = false
		for _, asset := range release.Assets {
			if strings.Contains(strings.ToLower(asset.Name), "yacd") && strings.HasSuffix(asset.Name, ".tar.xz") {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
		errorMsg = "no suitable package found for yacd"
	}

	if downloadURL == "" {
		return errors.New(errorMsg)
	}

	logger.Print("Downloading " + repo + " from " + downloadURL)
	return downloadAndExtract(downloadURL, dest, format, isCore)
}

// 添加检查文件是否存在且可执行的函数
func checkExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	// 检查文件是否存在且有执行权限
	return !info.IsDir() && (info.Mode()&0111 != 0)
}

func downloadTools() {
	os.MkdirAll("core", os.ModePerm)
	os.MkdirAll("panel", os.ModePerm)

	// 检查 sing-box
	singboxPath := "core/singbox"
	if checkExecutable(singboxPath) {
		logger.Print("Singbox already exists, skipping download.")
	} else {
		logger.Print("Downloading Singbox...")
		err := downloadAndExtractFromGitHub("SagerNet", "sing-box", singboxPath, "tar.gz")
		if err != nil {
			logger.Print("Error downloading Singbox: " + err.Error())
		} else {
			logger.Print("Singbox downloaded.")
		}
	}

	// 检查 mosdns
	mosdnsPath := "core/mosdns"
	if checkExecutable(mosdnsPath) {
		logger.Print("Mosdns already exists, skipping download.")
	} else {
		logger.Print("Downloading Mosdns...")
		err := downloadAndExtractFromGitHub("IrineSistiana", "mosdns", mosdnsPath, "zip")
		if err != nil {
			logger.Print("Error downloading Mosdns: " + err.Error())
		} else {
			logger.Print("Mosdns downloaded.")
		}
	}

	// 检查 yacd 面板
	yacdPath := "panel/yacd"
	if _, err := os.Stat(filepath.Join(yacdPath, "index.html")); err == nil {
		logger.Print("yacd panel already exists, skipping download.")
	} else {
		logger.Print("Downloading yacd...")
		err := downloadAndExtractFromGitHub("haishanh", "yacd", yacdPath, "tar.xz")
		if err != nil {
			logger.Print("Error downloading yacd: " + err.Error())
		} else {
			logger.Print("yacd downloaded.")
		}
	}
}

type Subscription struct {
	URL    string `json:"url"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
}

var subscriptions []Subscription

func manageSubscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		logger.Print("Fetching subscriptions...")
		rows, err := db.Query("SELECT url, COALESCE(name, '') as name, COALESCE(status, '') as status FROM subscriptions")
		if err != nil {
			logger.Error("Error querying subscriptions: " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var subs []Subscription
		for rows.Next() {
			var sub Subscription
			if err := rows.Scan(&sub.URL, &sub.Name, &sub.Status); err != nil {
				logger.Error("Error scanning subscription: " + err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			subs = append(subs, sub)
		}

		if err := json.NewEncoder(w).Encode(subs); err != nil {
			logger.Error("Error encoding subscriptions: " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	case "POST":
		var sub Subscription
		if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
			logger.Error("Error decoding subscription: " + err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_, err := db.Exec("INSERT INTO subscriptions (url, status) VALUES (?, ?)",
			sub.URL, "pending")
		if err != nil {
			logger.Error("Error inserting subscription: " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := updateSubscription(sub); err != nil {
			logger.Error("Error updating subscription: " + err.Error())
			_, _ = db.Exec("UPDATE subscriptions SET status = ? WHERE url = ?",
				"error: "+err.Error(), sub.URL)
		} else {
			_, _ = db.Exec("UPDATE subscriptions SET status = ? WHERE url = ?",
				"active", sub.URL)
		}

		fmt.Fprintf(w, "{\"status\": \"subscription added\"}")

	default:
		logger.Warn("Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func updateAllSubscriptions() error {
	logger.Print("Updating all subscriptions...")

	rows, err := db.Query("SELECT url FROM subscriptions")
	if err != nil {
		return errors.New("failed to get subscriptions: " + err.Error())
	}
	defer rows.Close()

	var subs []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.URL); err != nil {
			logger.Error("Failed to scan subscription: " + err.Error())
			continue
		}
		subs = append(subs, sub)
	}

	for _, sub := range subs {
		if err := updateSubscription(sub); err != nil {
			logger.Error("Failed to update subscription " + sub.URL + ": " + err.Error())
		} else {
			logger.Print("Successfully updated subscription: " + sub.URL)
		}
	}

	return nil
}

type DNSConfig struct {
	Address string `json:"address"`
	Type    string `json:"type"` // "standard" or "doh"
}

var dnsConfigs []DNSConfig

func manageDNS(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		logger.Print("Fetching DNS configurations...")
		if err := json.NewEncoder(w).Encode(dnsConfigs); err != nil {
			logger.Error("Error encoding DNS configurations: " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "POST":
		var dns DNSConfig
		if err := json.NewDecoder(r.Body).Decode(&dns); err != nil {
			logger.Error("Error decoding DNS configuration: " + err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		dnsConfigs = append(dnsConfigs, dns)
		logger.Print("DNS configuration added.")
		fmt.Fprintf(w, "{\"status\": \"DNS configuration added\"}")
	default:
		logger.Warn("Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := bcrypt.CompareHashAndPassword(adminPasswordHash, []byte(req.OldPassword)); err != nil {
		http.Error(w, "Old password is incorrect", http.StatusUnauthorized)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error updating password", http.StatusInternalServerError)
		return
	}

	adminPasswordHash = hash
	fmt.Fprintf(w, "{\"status\": \"Password updated\"}")
}

func loadSubscriptions() error {
	file, err := os.Open(subscriptionFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在时忽略错误
		}
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(&subscriptions)
}

func loadRules() error {
	file, err := os.Open(rulesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(&rules)
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "nodes.db")
	if err != nil {
		return err
	}

	// 删除旧的数据库表
	_, err = db.Exec("DROP TABLE IF EXISTS nodes")
	if err != nil {
		return err
	}

	// 创建节点表
	createNodesTable := `CREATE TABLE IF NOT EXISTS nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT,
		config TEXT,
		source TEXT
	)`
	if _, err = db.Exec(createNodesTable); err != nil {
		return err
	}

	// 创建订阅表
	createSubsTable := `CREATE TABLE IF NOT EXISTS subscriptions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		url TEXT UNIQUE,
		name TEXT,
		status TEXT
	)`
	if _, err = db.Exec(createSubsTable); err != nil {
		return err
	}

	return nil
}

func getSystemStatus() map[string]string {
	status := make(map[string]string)
	status["os"] = runtime.GOOS
	status["arch"] = runtime.GOARCH
	// 可以根据需要添加更多系统状态信息
	return status
}

func configureProxy() {
	switch runtime.GOOS {
	case "linux":
		logger.Print("Configuring proxy for Linux...")
	case "darwin":
		logger.Print("Configuring proxy for macOS...")
	case "windows":
		logger.Print("Configuring proxy for Windows...")
	default:
		logger.Print("Unsupported OS")
	}
}

func saveSubscriptions() error {
	file, err := os.Create(subscriptionFile)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(subscriptions)
}

func saveRules() error {
	file, err := os.Create(rulesFile)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(rules)
}

// 添加新的结构体定义
type Node struct {
	ID     int    `json:"id"`
	Type   string `json:"type"`
	Config string `json:"config"`
	Source string `json:"source"` // 节点来源：manual 或 subscription
}

// 添加订阅更新函数
func updateSubscription(sub Subscription) error {
	resp, err := http.Get(sub.URL)
	if err != nil {
		return errors.New("failed to download subscription: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("subscription download failed with status code: " + fmt.Sprint(resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("failed to read subscription content: " + err.Error())
	}

	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		decoded = body
	}

	_, err = db.Exec("DELETE FROM nodes WHERE source = ?", sub.URL)
	if err != nil {
		return errors.New("failed to clean old nodes: " + err.Error())
	}

	// 解析节点内容（支持多行）
	nodes := strings.Split(string(decoded), "\n")
	for _, nodeStr := range nodes {
		nodeStr = strings.TrimSpace(nodeStr)
		if nodeStr == "" {
			continue
		}

		// 解析节点类型和配置
		nodeType, nodeConfig := parseNode(nodeStr)
		if nodeType == "" {
			continue
		}

		// 将节点保存到数据库
		_, err = db.Exec("INSERT INTO nodes (type, config, source) VALUES (?, ?, ?)",
			nodeType, nodeConfig, sub.URL)
		if err != nil {
			logger.Error("Failed to save node: " + err.Error())
			continue
		}
	}

	return nil
}

// 解析节点配置
func parseNode(nodeStr string) (nodeType string, nodeConfig string) {
	if strings.HasPrefix(nodeStr, "vmess://") {
		return "vmess", nodeStr[8:] // 返回不含前缀的配置
	} else if strings.HasPrefix(nodeStr, "ss://") {
		return "shadowsocks", nodeStr[5:]
	} else if strings.HasPrefix(nodeStr, "trojan://") {
		return "trojan", nodeStr[9:]
	}
	return "", ""
}

// 添加手动更新订阅的 API 处理函数
func updateSubscriptionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := updateAllSubscriptions(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "{\"status\": \"subscriptions updated\"}")
}

// 添加切换节点的处理函数
func switchNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeID := r.URL.Query().Get("id")
	if nodeID == "" {
		http.Error(w, "Node ID is required", http.StatusBadRequest)
		return
	}

	// 从数据库获取节点信息
	var node Node
	err := db.QueryRow("SELECT id, type, config, source FROM nodes WHERE id = ?", nodeID).Scan(&node.ID, &node.Type, &node.Config, &node.Source)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Node not found", http.StatusNotFound)
		} else {
			logger.Error("Error querying node: " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// 生成 Singbox 配置
	config, err := generateSingboxConfig(node)
	if err != nil {
		logger.Error("Error generating config: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 保存配置文件
	configPath := filepath.Join("config", "singbox.json")
	err = os.WriteFile(configPath, []byte(config), 0644)
	if err != nil {
		logger.Error("Error saving config: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 重启 Singbox
	if err := restartSingbox(configPath); err != nil {
		logger.Error("Error restarting singbox: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "node switched", "id": "` + nodeID + `"}`))
}

// 生成 Singbox 配置
func generateSingboxConfig(node Node) (string, error) {
	// 声明所需变量
	var (
		decodedConfig string
		serverConfig  string
		serverAddress string
		serverPort    int
		err           error
	)

	// 解码节点配置
	if node.Type == "vmess" {
		decoded, err := base64.StdEncoding.DecodeString(node.Config)
		if err != nil {
			return "", fmt.Errorf("%s", "failed to decode vmess config: "+err.Error())
		}
		decodedConfig = string(decoded)
	} else if node.Type == "shadowsocks" {
		// 处理URL编码并移除注释部分
		decodedConfig = strings.ReplaceAll(node.Config, "%20", " ")
		decodedConfig = strings.Split(decodedConfig, "#")[0]
		logger.Printf("Shadowsocks config after URL decode: %s", decodedConfig)

		// 检查并移除ss://前缀
		if strings.HasPrefix(decodedConfig, "ss://") {
			decodedConfig = decodedConfig[5:]
		}
		logger.Printf("Shadowsocks config after removing prefix: %s", decodedConfig)

		// 尝试解析两种格式:
		// 1. base64(method:password)@server:port
		// 2. base64(method:password@server:port)
		parts := strings.Split(decodedConfig, "@")
		logger.Printf("Split parts: %v", parts)
		if len(parts) == 2 {
			// 格式1: base64(method:password)@server:port
			logger.Printf("Trying to decode part 1: %s", parts[0])
			decoded, err := base64.StdEncoding.DecodeString(parts[0])
			if err != nil {
				// 尝试URL-safe base64解码
				logger.Printf("Standard base64 decode failed, trying URL-safe: %v", err)
				decoded, err = base64.URLEncoding.DecodeString(parts[0])
				if err != nil {
					return "", fmt.Errorf("failed to decode shadowsocks method and password: %v", err)
				}
			}
			logger.Printf("Decoded method and password: %s", string(decoded))

			// 解析方法和密码
			methodAndPassword := strings.Split(string(decoded), ":")
			if len(methodAndPassword) != 2 {
				return "", fmt.Errorf("invalid shadowsocks method and password format: %v", methodAndPassword)
			}
			logger.Printf("Method and password parts: %v", methodAndPassword)

			// 解析地址和端口
			serverParts := strings.Split(parts[1], ":")
			if len(serverParts) != 2 {
				return "", fmt.Errorf("invalid shadowsocks address and port format")
			}
			logger.Printf("Server parts: %v", serverParts)

			serverAddress = serverParts[0]
			serverPort, err = strconv.Atoi(serverParts[1])
			if err != nil {
				return "", fmt.Errorf("invalid port number: %v", serverParts[1])
			}

			serverConfig = `"method": "` + methodAndPassword[0] + `",
				"password": "` + methodAndPassword[1] + `"`
		} else {
			// 格式2: base64(method:password@server:port)
			logger.Printf("Trying to decode full config: %s", decodedConfig)
			decoded, err := base64.URLEncoding.DecodeString(decodedConfig)
			if err != nil {
				// 尝试标准base64解码
				logger.Printf("URL-safe base64 decode failed, trying standard: %v", err)
				decoded, err = base64.StdEncoding.DecodeString(decodedConfig)
				if err != nil {
					return "", fmt.Errorf("failed to decode shadowsocks config: %v", err)
				}
			}
			logger.Printf("Decoded full config: %s", string(decoded))

			// 解析完整配置
			parts = strings.Split(string(decoded), "@")
			if len(parts) != 2 {
				return "", fmt.Errorf("invalid shadowsocks config format")
			}

			// 解析方法和密码
			methodAndPassword := strings.Split(parts[0], ":")
			if len(methodAndPassword) != 2 {
				return "", fmt.Errorf("invalid shadowsocks method and password format")
			}

			// 解析地址和端口
			serverParts := strings.Split(parts[1], ":")
			if len(serverParts) != 2 {
				return "", fmt.Errorf("invalid shadowsocks address and port format")
			}

			serverAddress = serverParts[0]
			serverPort, err = strconv.Atoi(serverParts[1])
			if err != nil {
				return "", fmt.Errorf("invalid port number: %v", serverParts[1])
			}

			serverConfig = `"method": "` + methodAndPassword[0] + `",
				"password": "` + methodAndPassword[1] + `"`
		}
	} else if node.Type == "trojan" {
		decodedConfig = node.Config
	} else {
		return "", fmt.Errorf("%s", "unsupported node type: "+node.Type)
	}

	// 根据节点类型生成具体配置
	if node.Type == "vmess" {
		var vmessConfig struct {
			Add  string      `json:"add"`
			Port interface{} `json:"port"`
			ID   string      `json:"id"`
			Net  string      `json:"net"`
			Path string      `json:"path"`
			TLS  string      `json:"tls"`
		}
		if err := json.Unmarshal([]byte(decodedConfig), &vmessConfig); err != nil {
			return "", fmt.Errorf("%s", "failed to parse vmess config: "+err.Error())
		}
		serverAddress = vmessConfig.Add

		// 处理端口值
		switch p := vmessConfig.Port.(type) {
		case float64:
			serverPort = int(p)
		case string:
			serverPort, err = strconv.Atoi(p)
			if err != nil {
				return "", fmt.Errorf("invalid port number: %v", p)
			}
		default:
			return "", fmt.Errorf("unexpected port type: %T", p)
		}

		serverConfig = `"uuid": "` + vmessConfig.ID + `",
			"network": "` + vmessConfig.Net + `",
			"transport": {
				"type": "` + vmessConfig.Net + `",
				"path": "` + vmessConfig.Path + `"
			},
			"tls": {
				"enabled": ` + fmt.Sprint(vmessConfig.TLS == "tls") + `
			}`
	}

	// 使用字符串拼接生成最终配置
	return `{
		"log": {
			"level": "info",
			"timestamp": true
		},
		"dns": {
			"servers": [
				{
					"tag": "dns-remote",
					"address": "tcp://8.8.8.8",
					"detour": "proxy"
				},
				{
					"tag": "dns-local",
					"address": "local",
					"detour": "direct"
				}
			],
			"rules": [
				{
					"domain": "cn",
					"server": "dns-local"
				}
			]
		},
		"inbounds": [
			{
				"type": "mixed",
				"tag": "mixed-in",
				"listen": "127.0.0.1",
				"listen_port": 1080
			}
		],
		"outbounds": [
			{
				"type": "` + node.Type + `",
				"tag": "proxy",
				"server": "` + serverAddress + `",
				"server_port": ` + fmt.Sprint(serverPort) + `,
				` + serverConfig + `
			},
			{
				"type": "direct",
				"tag": "direct"
			},
			{
				"type": "block",
				"tag": "block"
			}
		],
		"route": {
			"rules": [
				{
					"domain": "cn",
					"geoip": "cn",
					"outbound": "direct"
				}
			],
			"final": "proxy"
		}
	}`, nil
}

// 重启 Singbox
func restartSingbox(configPath string) error {
	// 获取当前进程
	processes, err := findProcess("singbox")
	if err != nil {
		return err
	}

	// 停止现有进程
	for _, p := range processes {
		if err := p.Kill(); err != nil {
			logger.Error("Error killing process: " + err.Error())
		}
	}

	// 启动新进程
	cmd := exec.Command("./core/singbox", "run", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

// 查找进程
func findProcess(name string) ([]*os.Process, error) {
	var processes []*os.Process
	if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq "+name+".exe")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, name) {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					if pid, err := strconv.Atoi(fields[1]); err == nil {
						if p, err := os.FindProcess(pid); err == nil {
							processes = append(processes, p)
						}
					}
				}
			}
		}
	} else {
		cmd := exec.Command("pgrep", name)
		output, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				return nil, nil
			}
			return nil, err
		}
		for _, line := range strings.Split(string(output), "\n") {
			if line != "" {
				if pid, err := strconv.Atoi(line); err == nil {
					if p, err := os.FindProcess(pid); err == nil {
						processes = append(processes, p)
					}
				}
			}
		}
	}
	return processes, nil
}

func main() {
	// 启动时下载工具
	go downloadTools()

	logger.Print("服务器启动中...")

	// 启动时立即更新一次
	go func() {
		if err := updateAllSubscriptions(); err != nil {
			logger.Error("Failed to update subscriptions: " + err.Error())
		}
	}()

	// 启动时配置网络
	go configureNetwork()

	// 启动时管理 Singbox 和 Mosdns
	go manageSingbox()
	go manageMosdns()

	// 启动时进行节点分组
	go groupNodes()

	// 启动时进行节点测速
	go testNodeSpeed()

	// 启动时更新规则
	go updateRules()

	// 启动时启用去广告功能
	go toggleAdBlock(true)

	// 定时更新
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for {
			<-ticker.C
			updateAllSubscriptions()
			updateRules()
		}
	}()

	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(getSystemStatus())
	})

	http.HandleFunc("/api/nodes", manageNodes)

	http.HandleFunc("/api/rules", manageRules)

	http.HandleFunc("/api/settings", manageSettings)

	http.HandleFunc("/api/login", login)

	http.HandleFunc("/api/change-password", changePassword)

	http.HandleFunc("/api/logs", viewLogs)

	http.HandleFunc("/api/detailed-logs", detailedLogs)

	http.HandleFunc("/api/subscriptions", manageSubscriptions)

	http.HandleFunc("/api/subscriptions/update", updateSubscriptionsHandler)

	http.HandleFunc("/api/dns", manageDNS)

	// 启动时备份配置
	go backupConfig()

	// 启动时进行增强备份
	go enhancedBackup()

	// 启动时配置代理
	go configureProxy()

	// 调用未使用的函数
	go authenticate(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "已认证!")
	})
	go restoreConfig()
	go saveSubscriptions()
	go saveRules()

	// 添加节点切换的路由
	http.HandleFunc("/api/nodes/switch/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) != 5 {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}
		r.URL.RawQuery = "id=" + parts[4]
		switchNode(w, r)
	})

	logger.Print("服务器启动完成，监听端口 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatal("服务器启动失败: " + err.Error())
	}
}
