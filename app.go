package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"
)

const (
	Port              = 8000
	DefaultThreads    = 1000
	RangesFile        = "ranges.txt"
	OutputFile        = "found_ips.txt"
	ConnectionTimeout = 1500 * time.Millisecond
	UpdateInterval    = 100 * time.Millisecond
	BatchSize         = 1000000
	AutoclearFound    = true
	MaxIPQueueSize    = 50000000
	ProgressBarLength = 40
	MaxRangeSize      = 50000000
	ProgressChars     = "█"
)

var (
	checkedIPs    uint64
	successfulIPs uint64
	totalIPs      uint64
	stopScan      atomic.Bool
	wg            sync.WaitGroup
	ipQueue       chan string
	outputFile    *os.File
	outputMutex   sync.Mutex
	ipQueueDone   = make(chan struct{})
	startTime     time.Time
	version       = "1.3b"
	author        = "SanyaPivo"
	threads       int
	
	red    = color.New(color.FgRed)
	green  = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	blue   = color.New(color.FgBlue)
	cyan   = color.New(color.FgCyan)
	white  = color.New(color.FgWhite)
)

func main() {
	printBanner()
	threads = getThreadCount()
	ipQueue = make(chan string, MaxIPQueueSize)

	ctx, cancel := context.WithCancel(context.Background())
	setupSignalHandler(cancel)

	if _, err := os.Stat(RangesFile); os.IsNotExist(err) {
		red.Printf("[✗] Файл %s не найден!\n", RangesFile)
		log.Fatal()
	}

	prepareOutputFile()

	loadCompleted := make(chan struct{})
	go func() {
		loadIPRanges()
		close(loadCompleted)
	}()

	<-loadCompleted
	close(ipQueueDone)

	if atomic.LoadUint64(&totalIPs) == 0 {
		red.Println("\n[✗] Нет IP для сканирования!")
		white.Println("    Проверьте формат файла ranges.txt")
		white.Println("    Пример диапазона: 192.168.0.1-192.168.0.255")
		white.Println("    Пример CIDR: 192.168.0.0/24")
		return
	}

	cyan.Printf("\n[✓] Начинаем сканирование %s IP...\n", formatNumber(atomic.LoadUint64(&totalIPs)))
	white.Println(strings.Repeat("-", 60))

	go titleUpdater(ctx)
	startWorkers(ctx)

	waitForCompletion()
	printFinalStats()
}

func printBanner() {
	clearScreen()
	banner := ` 
 ██████╗  ██████╗ ███████╗██████╗ ███████╗
██╔════╝ ██╔═══██╗██╔════╝██╔══██╗██╔════╝
██║  ███╗██║   ██║█████╗  ██████╔╝███████╗
██║   ██║██║   ██║██╔══╝  ██╔═══╝ ╚════██║
╚██████╔╝╚██████╔╝██║     ██║     ███████║
 ╚═════╝  ╚═════╝ ╚═╝     ╚═╝     ╚══════╝
                                          
`
	cyan.Println(banner)
	yellow.Printf("Golang FastPortScanner v%s | by %s\n\n", version, author)
	yellow.Printf("Join our Discord: https://discord.gg/zcqH9jGKdQ\n")
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func getThreadCount() int {
	if len(os.Args) > 1 {
		t, err := strconv.Atoi(os.Args[1])
		if err == nil && t > 0 {
			return t
		}
		yellow.Printf("[!] Некорректное число потоков: %s. Использую значение по умолчания (%d)\n", os.Args[1], DefaultThreads)
	}
	return DefaultThreads
}

func setupSignalHandler(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		yellow.Println("\n[!] Получен сигнал прерывания, останавливаю сканирование...")
		stopScan.Store(true)
		cancel()
	}()
}

func prepareOutputFile() {
	if AutoclearFound {
		if err := os.WriteFile(OutputFile, []byte{}, 0644); err != nil {
			red.Printf("[!] Ошибка очистки файла: %v\n", err)
		} else {
			green.Println("[✓] Файл результатов очищен")
		}
	}

	var err error
	outputFile, err = os.OpenFile(OutputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		red.Printf("[!] Ошибка открытия файла: %v\n", err)
		log.Fatal()
	}
}

func titleUpdater(ctx context.Context) {
	startTime = time.Now()
	ticker := time.NewTicker(UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if stopScan.Load() {
				return
			}
			updateProgress()
		}
	}
}

func updateProgress() {
	checked := atomic.LoadUint64(&checkedIPs)
	success := atomic.LoadUint64(&successfulIPs)
	total := atomic.LoadUint64(&totalIPs)

	if total == 0 {
		return
	}

	progress := float64(checked) / float64(total)
	elapsed := time.Since(startTime)
	ipsPerSec := float64(checked) / elapsed.Seconds()
	remaining := time.Duration(float64(elapsed) / progress * (1 - progress)).Round(time.Second)

	filled := int(ProgressBarLength * progress)
	empty := ProgressBarLength - filled


	progressChar := '▌'
	if filled < ProgressBarLength {
		partial := float64(ProgressBarLength*progress) - float64(filled)
		charIndex := int(partial * float64(len(ProgressChars)-1))
		progressChar = rune(ProgressChars[charIndex])
	}


	var barColor *color.Color
	switch {
	case progress >= 0.75:
		barColor = color.New(color.FgGreen)
	case progress >= 0.25:
		barColor = color.New(color.FgYellow)
	default:
		barColor = color.New(color.FgRed)
	}


	var speedColor *color.Color
	switch {
	case ipsPerSec > 10000:
		speedColor = color.New(color.FgGreen, color.Bold)
	case ipsPerSec > 5000:
		speedColor = color.New(color.FgCyan)
	default:
		speedColor = color.New(color.FgYellow)
	}

	var remainingColor *color.Color
	switch {
	case remaining < time.Minute:
		remainingColor = color.New(color.FgGreen)
	case remaining < 5*time.Minute:
		remainingColor = color.New(color.FgYellow)
	default:
		remainingColor = color.New(color.FgRed)
	}

	// Сборка прогресс-бара
	bar := barColor.Sprint(strings.Repeat("▌", filled)+string(progressChar)) +
		color.New(color.FgWhite).Sprint(strings.Repeat(" ", empty))

	// Сборка статистики
	stats := fmt.Sprintf(
		"Проверено: %s/%s | Открыто: %s | Скорость: %s | Осталось: %s",
		color.New(color.FgCyan).Sprint(formatNumber(checked)),
		color.New(color.FgWhite).Sprint(formatNumber(total)),
		color.New(color.FgGreen).Sprint(formatNumber(success)),
		speedColor.Sprint(formatNumber(uint64(ipsPerSec))+" IP/сек"),
		remainingColor.Sprint(remaining),
	)

	line := fmt.Sprintf("[•] Прогресс: %s %.1f%% | %s", bar, progress*100, stats)
	fmt.Printf("\r%s", line)
}

func formatNumber(n uint64) string {
	s := strconv.FormatUint(n, 10)
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteRune(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func startWorkers(ctx context.Context) {
	fmt.Printf("[•] Запуск %d потоков...\n", threads)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(ctx)
	}
}

func worker(ctx context.Context) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ip, ok := <-ipQueue:
			if !ok {
				return
			}
			if stopScan.Load() {
				return
			}

			if checkPort(ip, Port) {
				atomic.AddUint64(&successfulIPs, 1)
				saveFoundIP(ip)
			}

			atomic.AddUint64(&checkedIPs, 1)
		}
	}
}

func checkPort(ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, ConnectionTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func saveFoundIP(ip string) {
	outputMutex.Lock()
	defer outputMutex.Unlock()

	if _, err := outputFile.WriteString(ip + "\n"); err != nil {
		log.Printf("[!] Ошибка записи IP: %v", err)
	}
}

func loadIPRanges() {
	file, err := os.Open(RangesFile)
	if err != nil {
		red.Printf("[✗] Ошибка открытия файла %s: %v\n", RangesFile, err)
		log.Fatal()
	}
	defer file.Close()

	cyan.Printf("\n[•] Чтение файла %s...\n", RangesFile)

	scanner := bufio.NewScanner(file)
	loaded := uint64(0)
	lineNum := 0
	validRanges := 0
	skippedRanges := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cleanLine := strings.ReplaceAll(line, " ", "")

		// Обработка CIDR
		if strings.Contains(cleanLine, "/") {
			_, ipNet, err := net.ParseCIDR(cleanLine)
			if err != nil {
				yellow.Printf("[!] Строка %d: '%s' — неверный CIDR: %v\n", lineNum, line, err)
				skippedRanges++
				continue
			}

			if ipNet.IP.To4() == nil {
				yellow.Printf("[!] Строка %d: '%s' — IPv6 CIDR не поддерживается\n", lineNum, line)
				skippedRanges++
				continue
			}

			start := ipToUint32(ipNet.IP.To4())
			mask := binary.BigEndian.Uint32(ipNet.Mask)
			end := start | (^mask)

			rangeSize := end - start + 1
			if rangeSize > MaxRangeSize {
				fmt.Printf("[!] Строка %d: '%s' — слишком большой CIDR диапазон (%d IP > %d)\n",
					lineNum, line, rangeSize, MaxRangeSize)
				skippedRanges++
				continue
			}

			for i := start; i <= end; i++ {
				ip := uint32ToIP(i)
				select {
				case ipQueue <- ip.String():
					loaded++
				case <-time.After(1 * time.Second):
					fmt.Printf("[!] Таймаут при добавлении IP\n")
					return
				}
			}

			validRanges++
			fmt.Printf("\r[•] Загружено %s IP из %d диапазонов (пропущено %d)",
				formatNumber(loaded), validRanges, skippedRanges)
			continue
		}


		if !strings.Contains(cleanLine, "-") {
			fmt.Printf("[!] Строка %d: '%s' — неверный формат (ожидается CIDR или диапазон)\n", lineNum, line)
			skippedRanges++
			continue
		}

		parts := strings.SplitN(cleanLine, "-", 2)
		startIP, endIP := parts[0], parts[1]

		if strings.Contains(startIP, ":") || strings.Contains(endIP, ":") {
			continue
		}

		start := net.ParseIP(startIP)
		end := net.ParseIP(endIP)
		if start == nil || end == nil {
			fmt.Printf("[!] Строка %d: '%s' — неверный IP-формат\n", lineNum, line)
			skippedRanges++
			continue
		}

		startUint := ipToUint32(start.To4())
		endUint := ipToUint32(end.To4())
		if startUint > endUint {
			startUint, endUint = endUint, startUint
		}

		rangeSize := endUint - startUint + 1
		if rangeSize > MaxRangeSize {
			fmt.Printf("[!] Строка %d: '%s' — слишком большой диапазон (%d IP > %d)\n",
				lineNum, line, rangeSize, MaxRangeSize)
			skippedRanges++
			continue
		}

		for i := startUint; i <= endUint; i++ {
			ip := uint32ToIP(i)
			select {
			case ipQueue <- ip.String():
				loaded++
			case <-time.After(1 * time.Second):
				fmt.Printf("[!] Таймаут при добавлении IP\n")
				return
			}
		}

		validRanges++
		fmt.Printf("\r[•] Загружено %s IP из %d диапазонов (пропущено %d)",
			formatNumber(loaded), validRanges, skippedRanges)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("[✗] Ошибка чтения файла: %v", err)
	}

	atomic.StoreUint64(&totalIPs, loaded)
	fmt.Printf("\n[✓] Успешно загружено %s IP из %d диапазонов (пропущено %d)\n",
		formatNumber(loaded), validRanges, skippedRanges)

	if loaded == 0 {
		fmt.Println("[✗] В файле нет валидных IPv4 диапазонов!")
		fmt.Println("    Пример корректного формата: 192.168.0.1-192.168.0.255")
		fmt.Println("    Пример CIDR: 192.168.0.0/24")
	} else {
		fmt.Println(strings.Repeat("-", 60))
	}
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	)
}

func waitForCompletion() {
	wg.Wait()
}

func printFinalStats() {
	elapsed := time.Since(startTime).Round(time.Second)
	checked := atomic.LoadUint64(&checkedIPs)
	success := atomic.LoadUint64(&successfulIPs)
	rate := float64(checked) / elapsed.Seconds()

	white.Println(strings.Repeat("=", 60))
	cyan.Printf("%sСканирование завершено!%s\n", centerText("", 26), centerText("", 26))
	white.Printf("%sВремя работы: %s%s\n", centerText("", 20), centerText(elapsed.String(), 20), centerText("", 20))
	white.Printf("%sПроверено IP: %s%s\n", centerText("", 20), centerText(formatNumber(checked), 20), centerText("", 20))
	green.Printf("%sНайдено открытых: %s%s\n", centerText("", 20), centerText(formatNumber(success), 20), centerText("", 20))
	yellow.Printf("%sСредняя скорость: %s IP/сек%s\n", centerText("", 20), centerText(formatNumber(uint64(rate)), 20), centerText("", 20))
	white.Println(strings.Repeat("=", 60))
}

func centerText(text string, width int) string {
	textLen := utf8.RuneCountInString(text)
	if textLen >= width {
		return text
	}
	padding := (width - textLen) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-textLen-padding)
}
