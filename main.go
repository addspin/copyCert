package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func main() {
	// Чтение логина
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Введите логин: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	// Безопасное чтение пароля (без отображения)
	fmt.Print("Введите пароль: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("\nОшибка при чтении пароля: %v\n", err)
		return
	}
	password := string(bytePassword)
	fmt.Println() // Перевод строки после ввода пароля

	// Чтение публичного ключа
	pubKey, err := os.ReadFile("id.pub")
	if err != nil {
		fmt.Printf("Ошибка чтения id.pub: %v\n", err)
		return
	}
	pubKeyStr := strings.TrimSpace(string(pubKey))

	// Чтение списка IP адресов
	file, err := os.Open("ip.txt")
	if err != nil {
		fmt.Printf("Ошибка открытия ip.txt: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() { // Цикл, который читает файл построчно
		ipAddress := strings.TrimSpace(scanner.Text())
		if ipAddress == "" {
			continue
		}

		fmt.Printf("\nПодключение к %s...\n", ipAddress)

		// Настройка SSH клиента
		config := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		// Подключение к серверу
		client, err := ssh.Dial("tcp", ipAddress+":22", config)
		if err != nil {
			fmt.Printf("Ошибка подключения к SSH: %v\n", err)
			continue
		}
		defer client.Close()

		// Создание новой сессии
		session, err := client.NewSession()
		if err != nil {
			fmt.Printf("Ошибка создания сессии: %v\n", err)
			continue
		}
		defer session.Close()

		// Проверка существования ключа и добавление если его нет
		checkCommand := fmt.Sprintf(`
        mkdir -p ~/.ssh && 
        touch ~/.ssh/authorized_keys && 
        if ! grep -qF "%s" ~/.ssh/authorized_keys; then 
            echo '%s' >> ~/.ssh/authorized_keys && 
            echo "Ключ успешно добавлен"
        else 
            echo "Ключ уже существует"
        fi`, pubKeyStr, pubKeyStr)

		output, err := session.CombinedOutput(checkCommand)
		if err != nil {
			fmt.Printf("Ошибка выполнения команды: %v\n", err)
			continue
		}

		fmt.Println(string(output))
	}
}
