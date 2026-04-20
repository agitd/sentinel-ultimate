package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Result описывает структуру найденного пути для JSON
type Result struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Timestamp  string `json:"timestamp"`
}

func main() {
	// 1. Настройка параметров (Флаги)
	target := flag.String("u", "", "URL цели (например, http://myschool.ru)")
	wordlistPath := flag.String("w", "", "Путь к словарю (например, list.txt)")
	singlePath := flag.String("p", "", "Проверить только один путь (например, admin)")
	outputPath := flag.String("o", "reports/results.json", "Путь для сохранения JSON отчета")
	threads := flag.Int("t", 10, "Количество параллельных потоков")
	delay := flag.Int("d", 200, "Базовая задержка между запросами (мс)")
	verbose := flag.Bool("v", false, "Подробный режим (выводить все попытки)")

	// +++ ДОБАВЛЕНО: Новые флаги для максимального покрытия +++
	extensions := flag.String("x", "", "Расширения через запятую (напр: php,bak,zip,old)")
	vhost := flag.String("H", "", "Кастомный заголовок Host (для поиска скрытых поддоменов)")
	ignoreStatuses := flag.String("is", "404,400", "Статусы для игнора (через запятую)")

	// Настройка кастомного вывода помощи
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "=== Sentinel-Go Fuzzer v4.0 ===\n")
		fmt.Fprintf(os.Stderr, "Автор: Твой мощный проект на Go\n\n")
		fmt.Fprintf(os.Stderr, "Параметры запуска:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Проверка обязательного параметра
	if *target == "" {
		fmt.Println("[!] Ошибка: Не указана цель (-u)")
		flag.Usage()
		return
	}

	// 2. Подготовка окружения
	if _, err := os.Stat("reports"); os.IsNotExist(err) {
		os.Mkdir("reports", 0755)
	}

	results := make(chan Result, 100)
	words := make(chan string, 100)
	var wg sync.WaitGroup

	fmt.Printf("[*] Цель: %s\n", *target)
	fmt.Printf("[*] Потоков: %d | Задержка: %dмс\n\n", *threads, *delay)

	// 3. Инициализация воркеров (потоков)
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Настраиваем клиент: таймаут и автоматические редиректы
			// Важно: мы не отключаем редиректы, чтобы видеть 301/302 статусы
			client := &http.Client{
				Timeout: 10 * time.Second,
				// +++ ДОБАВЛЕНО: Останавливаем авто-редирект, чтобы ловить куда нас посылают +++
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			for word := range words {
				jitter := 0
				if *delay > 0 {
					jitter = rand.Intn(*delay / 2)
				}
				time.Sleep(time.Duration(*delay+jitter) * time.Millisecond)

				cleanWord := strings.TrimSpace(word)
				if cleanWord == "" {
					continue
				}

				baseURL := strings.TrimSuffix(*target, "/")
				fullURL := baseURL + "/" + cleanWord

				req, err := http.NewRequest("GET", fullURL, nil)
				if err != nil {
					continue
				}

				// Маскировка под реальный браузер
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")

				// +++ ДОБАВЛЕНО: Подмена Host (VHost) +++
				if *vhost != "" {
					req.Host = *vhost
				}

				resp, err := client.Do(req)
				if err != nil {
					if *verbose {
						fmt.Printf("[!] Ошибка сети (%d): %s\n", workerID, fullURL)
					}
					continue
				}

				if *verbose {
					fmt.Printf("[Worker %d] %s - %d\n", workerID, fullURL, resp.StatusCode)
				}

				// +++ ДОБАВЛЕНО: Умная проверка статусов вместо жесткой привязки к 200 +++
				isIgnored := false
				for _, ig := range strings.Split(*ignoreStatuses, ",") {
					if fmt.Sprintf("%d", resp.StatusCode) == strings.TrimSpace(ig) {
						isIgnored = true
						break
					}
				}

				// Если статус не входит в список игнорируемых (например, не 404)
				if !isIgnored {
					// Оставляем твой "+++ НАЙДЕНО", но добавляем специфику для других статусов
					if resp.StatusCode == 200 {
						fmt.Printf("[+++] НАЙДЕНО (200): %s\n", fullURL)
					} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
						fmt.Printf("[%d REDIRECT] %s -> %s\n", resp.StatusCode, fullURL, resp.Header.Get("Location"))
					} else if resp.StatusCode == 403 {
						fmt.Printf("[403 FORBIDDEN] СКРЫТО, НО ЕСТЬ: %s\n", fullURL)
					} else if resp.StatusCode == 500 {
						fmt.Printf("[500 ERROR] ОШИБКА СЕРВЕРА (БАГ?): %s\n", fullURL)
					} else {
						fmt.Printf("[%d STATUS] НАЙДЕНО: %s\n", resp.StatusCode, fullURL)
					}

					results <- Result{
						URL:        fullURL,
						StatusCode: resp.StatusCode,
						Timestamp:  time.Now().Format(time.RFC3339),
					}
				}
				resp.Body.Close()
			}
		}(i)
	}

	// 4. Горутина для сбора результатов в массив
	var foundData []Result
	doneSaving := make(chan bool)
	go func() {
		for res := range results {
			foundData = append(foundData, res)
		}
		doneSaving <- true
	}()

	// 5. Распределение задач
	// +++ ДОБАВЛЕНО: Парсим расширения в массив для генерации путей +++
	extList := []string{""} // Всегда проверяем базовое слово (без расширения)
	if *extensions != "" {
		for _, p := range strings.Split(*extensions, ",") {
			extList = append(extList, "."+strings.TrimSpace(p))
		}
	}

	if *singlePath != "" {
		// +++ ДОБАВЛЕНО: Применяем расширения к одиночному пути +++
		for _, ext := range extList {
			words <- *singlePath + ext
		}
	} else if *wordlistPath != "" {
		file, err := os.Open(*wordlistPath)
		if err != nil {
			fmt.Printf("[!] Не удалось открыть словарь: %v\n", err)
		} else {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				baseWord := scanner.Text()
				// +++ ДОБАВЛЕНО: Множим каждое слово из словаря на все расширения +++
				for _, ext := range extList {
					words <- baseWord + ext
				}
			}
			file.Close()
		}
	} else {
		fmt.Println("[!] Ошибка: укажите словарь (-w) или путь (-p)")
		close(words)
		return
	}

	close(words)
	wg.Wait()

	close(results)
	<-doneSaving

	// 6. Итоговое сохранение в JSON
	if len(foundData) > 0 {
		jsonData, err := json.MarshalIndent(foundData, "", "  ")
		if err == nil {
			err = os.WriteFile(*outputPath, jsonData, 0644)
			if err != nil {
				fmt.Printf("[!] Ошибка записи файла: %v\n", err)
			} else {
				fmt.Printf("\n[!] Сканирование завершено. Найдено объектов (не в игноре): %d\n", len(foundData))
				fmt.Printf("[!] Отчет сохранен в: %s\n", *outputPath)
			}
		}
	} else {
		fmt.Println("\n[!] Поиск завершен. Ничего не найдено.")
	}
}
