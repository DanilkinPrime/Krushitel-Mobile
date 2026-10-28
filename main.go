package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Android IronScan GUI")

	var showMenu func()

	// -------------------------------------------------------------
	// КОМПОНЕНТЫ ДЛЯ РЕЖИМА 2 (Скан префиксов из айпи)
	// -------------------------------------------------------------
	titleLabel := widget.NewLabelWithStyle("Железный Сканер Dahua", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	statusLabel := widget.NewLabel("Настройки сканера")

	threadsEntry := widget.NewEntry()
	threadsEntry.SetText("50")
	threadsEntry.SetPlaceHolder("Максимум 1000")

	portEntry := widget.NewEntry()
	portEntry.SetText("37777")
	portEntry.SetPlaceHolder("Один порт (например: 37777, 8000)")

	outputEntry := widget.NewEntry()
	outputEntry.SetText("serials")
	outputEntry.SetPlaceHolder("Имя любого файла")

	filterEntry := widget.NewEntry()
	filterEntry.SetText("PAG, PAZ, PAJ")
	filterEntry.SetPlaceHolder("Пусто = все")

	logContent := widget.NewMultiLineEntry()
	logContent.SetPlaceHolder("Здесь будут отображаться шаги работы...")
	logContent.Disable()

	backToMenuBtn1 := widget.NewButton("Назад в меню", func() {
		showMenu()
	})

	var ruleEntry *widget.Button
	ruleEntry = widget.NewButton("Нет", func() {
		if ruleEntry.Text == "Да" {
			ruleEntry.SetText("Нет")
		} else {
			ruleEntry.SetText("Да")
		}
	})

	filePickerButton := widget.NewButton("Запуск", func() {
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				statusLabel.SetText("Ошибка: " + err.Error())
				return
			}
			if reader == nil {
				statusLabel.SetText("Выбор файла отменен")
				return
			}
			statusLabel.SetText("Обработка файла...")
			logContent.SetText("[SYSTEM] Файл успешно выбран. Инициализация...\n")

			go func(r fyne.URIReadCloser) {
				defer r.Close()
				appendLog(logContent, "[SYSTEM] Чтение сырых данных из файла...")
				data, err := io.ReadAll(r)
				if err != nil {
					statusLabel.SetText("Не удалось прочитать файл")
					appendLog(logContent, "[ERROR] Ошибка io.ReadAll: " + err.Error())
					return
				}
				appendLog(logContent, fmt.Sprintf("[SYSTEM] Прочитано %d байт. Очистка строк от символов \\r...", len(data)))

				concurrency, err := strconv.Atoi(strings.TrimSpace(threadsEntry.Text))
				if err != nil || concurrency < 1 {
					concurrency = 50
					threadsEntry.SetText("50")
				} else if concurrency > 1000 {
					concurrency = 1000
					threadsEntry.SetText("1000")
				}

				basePort, err := strconv.Atoi(strings.TrimSpace(portEntry.Text))
				if err != nil || basePort <= 0 || basePort > 65535 {
					basePort = 37777
					portEntry.SetText("37777")
				}

				outNameBase := strings.TrimSpace(outputEntry.Text)
				if outNameBase == "" {
					outNameBase = "serials"
				}

				var allowedModels []string
				filterText := strings.TrimSpace(filterEntry.Text)
				if filterText != "" {
					parts := strings.Split(filterText, ",")
					for _, p := range parts {
						cleanPart := strings.TrimSpace(p)
						if cleanPart != "" {
							allowedModels = append(allowedModels, strings.ToUpper(cleanPart))
						}
					}
				}

				cleanText := strings.ReplaceAll(string(data), "\r", "")
				lines := strings.Split(cleanText, "\n")
				var finalTargets []string

				appendLog(logContent, "[SYSTEM] Запуск парсинга целей...")
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					parsedLines := ParseTarget(line)
					if len(parsedLines) == 0 {
						appendLog(logContent, fmt.Sprintf("[WARN] Строка %d пропущена парсером: %s", i+1, line))
						continue
					}
					for _, parsed := range parsedLines {
						parsed = strings.TrimSpace(parsed)
						if parsed == "" {
							continue
						}
						if _, _, err := net.SplitHostPort(parsed); err == nil {
							finalTargets = append(finalTargets, parsed)
						} else {
							finalTargets = append(finalTargets, net.JoinHostPort(parsed, strconv.Itoa(basePort)))
						}
					}
				}

				appendLog(logContent, fmt.Sprintf("[SYSTEM] Анализ завершен. Найдено валидных целей: %d", len(finalTargets)))

				if len(finalTargets) == 0 {
					statusLabel.SetText("Валидные IP не найдены")
					appendLog(logContent, "[ERROR] Сканирование невозможно: список целей пуст.")
					return
				}

				defaultFileName := fmt.Sprintf("prefix.txt")

				saveDialog := dialog.NewFileSave(func(outFile fyne.URIWriteCloser, err error) {
					var checkedCount uint64 = 0
					successCount := 0
					if err != nil {
						statusLabel.SetText("Ошибка создания файла: " + err.Error())
						return
					}
					if outFile == nil {
						statusLabel.SetText("Сохранение результатов отменено")
						return
					}
					appendLog(logContent, "[SYSTEM] Выходной файл подтвержден. Запуск сетевых воркеров...")
					statusLabel.SetText(fmt.Sprintf("Сканирование %d целей...", len(finalTargets)))

					go func(out fyne.URIWriteCloser) {
						defer out.Close()
						opts := Options{
							Targets:     finalTargets,
							Port:        basePort,
							Timeout:     2 * time.Second,
							Concurrency: concurrency,
							Retries:     1,
							Seed:        0,
						}

						LogHook = func(format string, args ...any) {
    msg := fmt.Sprintf(format, args...)
    appendLog(logContent, "[CORE] " + msg)

    // Увеличиваем счетчик при каждом логе проверки
    atomic.AddUint64(&checkedCount, 1)

    // Обновляем статус на экране: сколько проверено из общего числа
    statusLabel.SetText(fmt.Sprintf("Проверено: %d / %d (Найдено: %d)", 
        atomic.LoadUint64(&checkedCount), len(finalTargets), successCount))
}

						ctx := context.Background()
						successCount := 0

						scanErr := Run(ctx, opts, func(res Result) {
							if res.Ok() {
								if len(allowedModels) > 0 {
									matched := false
									serialUpper := strings.ToUpper(res.Serial)
									for _, allowed := range allowedModels {
										if strings.Contains(serialUpper, allowed) {
											matched = true
											break
										}
									}
									if !matched {
										return
									}
								}

								finalSerial := res.Serial
								if ruleEntry.Text == "Нет" {
									if len(finalSerial) > 10 {
										finalSerial = finalSerial[:10]
									}
								}

								successCount++
								foundMsg := fmt.Sprintf("[FOUND] %s -> %s (%s)", res.Target, finalSerial, res.Model)
								appendLog(logContent, foundMsg)

								lineData := fmt.Sprintf("%s;%s;%s;%s\n", res.Target, finalSerial, res.Model, res.Firmware)
								if _, writeErr := out.Write([]byte(lineData)); writeErr != nil {
									appendLog(logContent, "[ERROR] Ошибка записи на диск: " + writeErr.Error())
								}
							}
						})

						if scanErr != nil {
							statusLabel.SetText("Ошибка работы: " + scanErr.Error())
							appendLog(logContent, "[ERROR] Сканер аварийно завершился: " + scanErr.Error())
						} else {
							statusLabel.SetText(fmt.Sprintf("Успешно! Найдено устройств: %d", successCount))
							appendLog(logContent, fmt.Sprintf("[SYSTEM] Сканирование полностью завершено. Успешных находок: %d", successCount))
						}
					}(outFile)
				}, myWindow)
				saveDialog.SetFileName(defaultFileName)
				saveDialog.Show()
			}(reader)
		}, myWindow)
		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		fileDialog.Show()
	})

	settingsForm := widget.NewForm(
		widget.NewFormItem("Потоки (Threads):", threadsEntry),
		widget.NewFormItem("Порт по умолчанию:", portEntry),
		widget.NewFormItem("Имя файла результатов:", outputEntry),
		widget.NewFormItem("Фильтр префиксов:", filterEntry),
		widget.NewFormItem("Добавлять серийники?:", ruleEntry),
	)

	scanContent := container.NewVBox(
		titleLabel,
		settingsForm,
		filePickerButton,
		statusLabel,
		logContent,
		backToMenuBtn1,
	)

	// -------------------------------------------------------------
	// КОМПОНЕНТЫ ДЛЯ РЕЖИМА 1 (Скан Облака по Префиксу + Запись txt)
	// -------------------------------------------------------------
	crashTitle := widget.NewLabelWithStyle("Режим 1: Сканирование Облака Dahua", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	crashStatus := widget.NewLabel("Ожидание ввода параметров...")

	prefixEntry := widget.NewEntry()
	prefixEntry.SetText("PAG1AA")
	prefixEntry.SetPlaceHolder("Впишите 10 символов префикса")

	cloudWorkersEntry := widget.NewEntry()
	cloudWorkersEntry.SetText("200")
	cloudWorkersEntry.SetPlaceHolder("Потоки (UDP сокеты)")

	cloudRpsEntry := widget.NewEntry()
	cloudRpsEntry.SetText("500")
	cloudRpsEntry.SetPlaceHolder("RPS Лимит запросов в сек")

	crashLog := widget.NewMultiLineEntry()
	crashLog.SetPlaceHolder("Логи сканирования облака...")
	crashLog.Disable()

	backToMenuBtn2 := widget.NewButton("Назад в меню", func() {
		showMenu()
	})

	var selectedCloudFile fyne.URIReadCloser

	btnChooseCloudFile := widget.NewButton("Выбрать файл", func() {
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				crashStatus.SetText("Ошибка выбора файла: " + err.Error())
				return
			}
			if reader == nil {
				crashStatus.SetText("Выбор файла отменен")
				return
			}
			selectedCloudFile = reader
			crashStatus.SetText("Выбран файл: " + reader.URI().Name())
		}, myWindow)
		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		fileDialog.Show()
	})

		// Запуск Облачного Сканирования с автоматическим определением режима (Префикс или Серийники)
	btnStartCloudScan := widget.NewButton("Запустить Скан", func() {
		prefix := strings.TrimSpace(prefixEntry.Text)
		if selectedCloudFile == nil {
			crashStatus.SetText("Ошибка: Сначала выберите исходный файл!")
			return
		}

		workers, err := strconv.Atoi(strings.TrimSpace(cloudWorkersEntry.Text))
		if err != nil || workers < 1 {
			workers = 50
		}

		rps, err := strconv.Atoi(strings.TrimSpace(cloudRpsEntry.Text))
		if err != nil || rps < 1 {
			rps = 100
		}

		// Читаем данные из входного файла перед запуском сканера
		defer selectedCloudFile.Close()
		fileData, err := io.ReadAll(selectedCloudFile)
		if err != nil {
			crashStatus.SetText("Не удалось прочитать исходный файл: " + err.Error())
			return
		}

		// Анализируем содержимое файла, чтобы понять: там префиксы или готовые серийники
		cleanText := strings.ReplaceAll(string(fileData), "\r", "")
		lines := strings.Split(cleanText, "\n")
		
		var sampleSerial string
		var totalValidLines int
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				totalValidLines++
				if sampleSerial == "" {
					sampleSerial = line // Запоминаем первую строку для теста
				}
			}
		}

		if totalValidLines == 0 {
			crashStatus.SetText("Ошибка: Выбранный файл пуст!")
			return
		}

		// === ИНТЕЛЛЕКТУАЛЬНАЯ ПРОВЕРКА СОДЕРЖИМОГО ФАЙЛА ===
		isFileWithSerials := len(sampleSerial) >= 13

		if isFileWithSerials {
			// ------------------------------------------------─────────
			// ВЕТКА А: В ФАЙЛЕ СЕРИЙНИКИ -> ЗАПУСКАЕМ МОДУЛЬ P2P-ЭКСПЛОЙТА
			// ------------------------------------------------─────────
			crashStatus.SetText("Обнаружены серийники! Запуск P2P модуля...")
			crashLog.SetText("[SYSTEM] Файл распознан как список серийных номеров. Инициализация воркеров...\n")

			connTimeout := 6 * time.Second
			moduleChan := make(chan P2PScanResult, 100)

			// Запуск модуля P2P-сканирования в фоновом потоке
			go func(fileContent string) {
				reader := strings.NewReader(fileContent)
				ctx := context.Background()
				
				err := StartP2PModuleScan(ctx, reader, workers, connTimeout, moduleChan)
				if err != nil {
					crashStatus.SetText("Ошибка P2P модуля!")
					appendLog(crashLog, "[ERROR] Прервано: " + err.Error())
					return
				}

				vulnerableCount := 0
				var currentIdx int64 = 0
				
				// Слайс для накопления успешных/уязвимых результатов в памяти мобильного устройства
				var reportLines []string

				// Читаем результаты из канала модуля в реальном времени
				for res := range moduleChan {
					atomic.AddInt64(&currentIdx, 1)
					statusText := fmt.Sprintf("[%s] Serial: %s | %s", res.Status, res.Serial, res.Details)
					
					// Выводим в лог на экране смартфона
					appendLog(crashLog, statusText)

					// Добавляем запись в отчет (вы можете форматировать строку по своему вкусу)
					reportLines = append(reportLines, fmt.Sprintf("%s;%s;%s\n", res.Serial, res.Status, res.Details))

					if res.Vulnerable {
						vulnerableCount++
					}

					crashStatus.SetText(fmt.Sprintf("P2P Прогресс: %d / %d (Уязвимо: %d)", atomic.LoadInt64(&currentIdx), totalValidLines, vulnerableCount))
				}

				crashStatus.SetText("Скан завершен! Выберите куда сохранить файл")
				appendLog(crashLog, "[SYSTEM] Проверка окончена. Вызов системного окна сохранения результатов...")

				defaultReportName := fmt.Sprintf("scanned.txt")

				// Вызывать UI компоненты (диалоги) в Fyne нужно строго в основном потоке, используем fyne.DoQueue
				fyne.DoQueue(func() {
					saveDialog := dialog.NewFileSave(func(outFile fyne.URIWriteCloser, err error) {
						if err != nil || outFile == nil {
							appendLog(crashLog, "[WARN] Сохранение отчета отменено пользователем.")
							return
						}
						defer outFile.Close()

						// Собираем весь текст отчета из памяти и пишем в файл
						fullReportText := strings.Join(reportLines, "")
						_, writeErr := outFile.Write([]byte(fullReportText))
						if writeErr != nil {
							appendLog(crashLog, "[ERROR] Не удалось записать файл: " + writeErr.Error())
						} else {
							appendLog(crashLog, "[SYSTEM] Отчет успешно сохранен на устройство!")
						}
					}, myWindow)
					
					saveDialog.SetFileName(defaultReportName)
					saveDialog.Show()
				})

			}(cleanText)

		} else {
			// ------------------------------------------------─────────
			// ВЕТКА Б: В ФАЙЛЕ ПРЕФИКСЫ -> СТАНДАРТНЫЙ СКАН ОБЛАКА DAHUA
			// ------------------------------------------------─────────
			if len(prefix) != 10 {
				crashStatus.SetText("Ошибка: Для скана облака префикс в поле должен быть 10 символов!")
				return
			}

			defaultCloudFile := fmt.Sprintf("serials.txt")
			
			saveCloudDialog := dialog.NewFileSave(func(outFile fyne.URIWriteCloser, err error) {
				if err != nil || outFile == nil {
					crashStatus.SetText("Сканирование отменено")
					return
				}
				crashStatus.SetText("Сканирование облака запущено...")
				crashLog.SetText("[SYSTEM] Выходной файл создан. Инициализация ScanCloudPrefix...\n")

				go func(out io.WriteCloser) {
					defer out.Close()
					ctx := context.Background()
					
					stats, err := ScanCloudPrefix(ctx, prefix, workers, rps, func(realSerial string) {
						appendLog(crashLog, fmt.Sprintf("[ALIVE] Найдена камера: %s", realSerial))
						_, _ = out.Write([]byte(realSerial + "\n"))
					})
					
					if err != nil {
						crashStatus.SetText("Ошибка запуска сканера!")
						appendLog(crashLog, "[ERROR] Прервано: " + err.Error())
						return
					}
					
					crashStatus.SetText("Готово!")
					appendLog(crashLog, fmt.Sprintf("Проверено: %d, Живых: %d", stats.TotalSent, stats.TotalHits))
				}(outFile)
			}, myWindow)
			
			saveCloudDialog.SetFileName(defaultCloudFile)
			saveCloudDialog.Show()
		}
	})


cloudForm := widget.NewForm(
widget.NewFormItem("Префикс (10 симв.):", prefixEntry),
widget.NewFormItem("Воркеры (Сокеты):", cloudWorkersEntry),
widget.NewFormItem("Лимит RPS:", cloudRpsEntry),
widget.NewFormItem("Исходный файл:", btnChooseCloudFile),
)
crashContent := container.NewVBox(
crashTitle,
cloudForm,
btnStartCloudScan,
crashStatus,
crashLog,
backToMenuBtn2,
)
// -------------------------------------------------------------
// МЕНЮ НАВИГАЦИИ
// -------------------------------------------------------------
showMenu = func() {
menuTitle := widget.NewLabelWithStyle("Выберите режим работы", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
btnCrash := widget.NewButton("1. Скан Облака (ScanCloudPrefix)", func() {
myWindow.SetContent(crashContent)
})
btnScan := widget.NewButton("2. Скан префиксов из айпи", func() {
myWindow.SetContent(scanContent)
})
menuLayout := container.NewVBox(
menuTitle,
layout.NewSpacer(),
btnCrash,
btnScan,
layout.NewSpacer(),
)
myWindow.SetContent(menuLayout)
}
showMenu()
myWindow.Resize(fyne.NewSize(450, 550))
myWindow.ShowAndRun()
}
func appendLog(entry *widget.Entry, text string) {
current := entry.Text
if current == "" {
entry.SetText(text)
} else {
entry.SetText(current + "\n" + text)
}
}
