package main

import (
	"context"
	"fmt"
	"io"
	"net"
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

	backToMenuBtn1 := widget.NewButton("Назад в меню", func() { showMenu() })

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

				timestamp := time.Now().Format("20060102_150405")
				defaultFileName := fmt.Sprintf("%s_%s.txt", outNameBase, timestamp)

				saveDialog := dialog.NewFileSave(func(outFile fyne.URIWriteCloser, err error) {
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

	backToMenuBtn2 := widget.NewButton("Назад в меню", func() { showMenu() })

	// Запуск Облачного Сканирования с сохранением в txt
	btnStartCloudScan := widget.NewButton("Запустить Облачный Скан", func() {
		prefix := strings.TrimSpace(prefixEntry.Text)
		if len(prefix) != 10 {
			crashStatus.SetText("Ошибка: префикс должен содержать 10 символов!")
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

		// Сначала просим пользователя указать файл для сохранения реальных серийных номеров
		timestamp := time.Now().Format("20060102_150405")
		defaultCloudFile := fmt.Sprintf("cloud_found_%s_%s.txt", prefix, timestamp)

		saveCloudDialog := dialog.NewFileSave(func(outFile fyne.URIWriteCloser, err error) {
			if err != nil {
				crashStatus.SetText("Ошибка создания файла: " + err.Error())
				return
			}
			if outFile == nil {
				crashStatus.SetText("Сканирование отменено (не выбран файл)")
				return
			}

			crashStatus.SetText("Сканирование запущено...")
crashLog.SetText("[SYSTEM] Выходной файл создан. Инициализация ScanCloudPrefix...\n")
// Запускаем сам скан в фоновом потоке
go func(out io.WriteCloser) {
defer out.Close()
ctx := context.Background()
stats, err := ScanCloudPrefix(ctx, prefix, workers, rps, func(realSerial string) {
// 1. Отображаем реальный найденный серийник в GUI логе
appendLog(crashLog, fmt.Sprintf("[ALIVE] Найдена камера: %s", realSerial))
// 2. Сразу записываем реальный серийный номер в txt файл на диск
lineData := fmt.Sprintf("%s\n", realSerial)
_, _ = out.Write([]byte(lineData))
})
if err != nil {
crashStatus.SetText("Ошибка запуска сканера!")
appendLog(crashLog, "[ERROR] Прервано: " + err.Error())
return
}
// Вывод результатов по окончании
crashStatus.SetText("Готово!")
appendLog(crashLog, fmt.Printf("Проверено: %d, Живых: %d", stats.TotalSent, stats.TotalHits))
}(outFile)
}, myWindow)
saveCloudDialog.SetFileName(defaultCloudFile)
saveCloudDialog.Show()
})
cloudForm := widget.NewForm(
widget.NewFormItem("Префикс (10 симв.):", prefixEntry),
widget.NewFormItem("Воркеры (Сокеты):", cloudWorkersEntry),
widget.NewFormItem("Лимит RPS:", cloudRpsEntry),
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
