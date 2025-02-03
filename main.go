package main

import (
	"bytes"
	"fmt"
	"time"

	"flag"

	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	CertsAdmin []struct {
		Name       string `mapstructure:"name"`
		Key        string `mapstructure:"key"`
		Password   string `mapstructure:"password"`
		PrivateKey string `mapstructure:"private_key"`
	} `mapstructure:"certs_admin"`
	Users []struct {
		Name string `mapstructure:"name"`
		Key  string `mapstructure:"key"`
	} `mapstructure:"users"`
	IP          []string `mapstructure:"ip"`
	RemoveUsers []struct {
		Name string `mapstructure:"name"`
	} `mapstructure:"remove_users"`
	RemoveUsersIP []string `mapstructure:"remove_users_ip"`
	AuthPassword  struct {
		Enable bool `mapstructure:"enable"`
	} `mapstructure:"auth_password"`
	TCPForwarding struct {
		Enable bool `mapstructure:"enable"`
	} `mapstructure:"tcpForwarding"`
	X11Forwarding struct {
		Enable bool `mapstructure:"enable"`
	} `mapstructure:"x11Forwarding"`
	AgentForwarding struct {
		Enable bool `mapstructure:"enable"`
	} `mapstructure:"agentForwarding"`
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("ошибка чтения конфига: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("ошибка парсинга конфига: %w", err)
	}

	return &config, nil
}

func main() {
	// Определяем флаги командной строки
	helpFlag := flag.Bool("h", false, "Показать справку")
	adminFlag := flag.Bool("a", false, "Копирование ключей админов на все серверы")
	createFlag := flag.Bool("c", false, "Создание пользователей и копирование их ключей")
	deleteFlag := flag.Bool("d", false, "Удаление пользователей")
	sshFlag := flag.Bool("s", false, "Установка параметров ssh")

	// Парсим флаги
	flag.Parse()

	// Если не указаны флаги или указан флаг -h, показываем справку
	if flag.NFlag() == 0 || *helpFlag {
		flag.Usage()
		return
	}

	// Загружаем конфигурацию
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Ошибка загрузки конфига: %v\n", err)
		return
	}

	// Шаг 1: Копирование ключей админов на все серверы
	if *adminFlag {
		for _, ip := range config.IP {
			for _, admin := range config.CertsAdmin {
				if err := copyAdminKey(ip, admin.Name, admin.Key, admin.Password, admin.PrivateKey); err != nil {
					fmt.Printf("Ошибка копирования ключа админа %s на %s: %v\n", admin.Name, ip, err)
					// Пропускаем этот сервер полностью, так как не сможем подключиться к нему для следующих операций
					continue
				}
				fmt.Printf("Ключ админа %s успешно скопирован на %s\n", admin.Name, ip)
			}
		}
	}

	// Шаг 2: Создание пользователей и копирование их ключей
	if *createFlag {
		for _, ip := range config.IP {
			for _, admin := range config.CertsAdmin {
				for _, user := range config.Users {
					if err := createUserAndCopyKey(ip, admin.Name, admin.PrivateKey, admin.Password,
						user.Name, user.Key); err != nil {
						fmt.Printf("Ошибка создания пользователя %s на %s (админ: %s): %v\n", user.Name, ip, admin.Name, err)
						continue
					}
					fmt.Printf("Пользователь %s успешно создан на %s\n", user.Name, ip)
				}
			}
		}
	}

	// Шаг 3: Удаление пользователей
	if *deleteFlag {
		for _, ip := range config.RemoveUsersIP {
			for _, admin := range config.CertsAdmin {
				for _, user := range config.RemoveUsers {
					if err := removeUser(ip, admin.Name, admin.PrivateKey, admin.Password, user.Name); err != nil {
						fmt.Printf("Ошибка удаления пользователя %s на %s (админ: %s): %v\n", user.Name, ip, admin.Name, err)
						continue
					}
					fmt.Printf("Пользователь %s успешно удален на %s\n", user.Name, ip)
				}
			}
		}
	}

	// Шаг 4: Настройка SSH
	if *sshFlag {
		for _, ip := range config.IP {
			for _, admin := range config.CertsAdmin {
				if err := configureSSH(ip, admin.Name, admin.PrivateKey, admin.Password,
					config.AuthPassword.Enable,
					config.TCPForwarding.Enable,
					config.X11Forwarding.Enable,
					config.AgentForwarding.Enable); err != nil {
					fmt.Printf("Ошибка настройки SSH на %s (админ: %s): %v\n", ip, admin.Name, err)
					continue
				}
				fmt.Printf("SSH настроен успешно на %s\n", ip)
			}
		}
	}
}

func copyAdminKey(ip, adminName, adminKey, adminPass, adminPrivateKey string) error {
	// Попытка подключения с использованием приватного ключа
	signer, err := ssh.ParsePrivateKey([]byte(adminPrivateKey))
	if err != nil {
		return fmt.Errorf("ошибка парсинга приватного ключа админа: %w", err)
	}

	config := &ssh.ClientConfig{
		User: adminName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", ip), config)
	if err != nil {
		// Если подключение с использованием приватного ключа не удалось, пробуем с паролем
		fmt.Printf("Не удалось подключиться на %s с использованием приватного ключа, пробуем с паролем: %v\n", ip, err)
		config.Auth = []ssh.AuthMethod{
			ssh.Password(adminPass),
		}
		client, err = ssh.Dial("tcp", fmt.Sprintf("%s:22", ip), config)
		if err != nil {
			return fmt.Errorf("ошибка подключения к SSH: %w", err)
		}
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ошибка создания SSH сессии: %w", err)
	}
	defer session.Close()

	// Добавляем проверку наличия ключа и вывод результата
	command := fmt.Sprintf(`
		mkdir -p /home/%[1]s/.ssh &&
		touch /home/%[1]s/.ssh/authorized_keys &&
		chmod 700 /home/%[1]s/.ssh &&
		chmod 600 /home/%[1]s/.ssh/authorized_keys &&
		if grep -qF "%[2]s" /home/%[1]s/.ssh/authorized_keys; then 
			echo "KEY_EXISTS"
		else 
			echo '%[2]s' >> /home/%[1]s/.ssh/authorized_keys &&
			echo "KEY_ADDED"
		fi &&
		chown -R %[1]s:%[1]s /home/%[1]s/.ssh
	`, adminName, adminKey)

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run(command); err != nil {
		return fmt.Errorf("ошибка выполнения команды: %w", err)
	}

	return nil
}

func configureSSH(ip, adminName, adminKey, adminPassword string,
	enablePasswordAuth, enableTCPForwarding, enableX11Forwarding, enableAgentForwarding bool) error {

	signer, err := ssh.ParsePrivateKey([]byte(adminKey))
	if err != nil {
		return fmt.Errorf("ошибка парсинга приватного ключа админа: %w", err)
	}

	config := &ssh.ClientConfig{
		User: adminName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", ip), config)
	if err != nil {
		return fmt.Errorf("ошибка подключения к SSH: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ошибка создания сессии: %w", err)
	}
	defer session.Close()

	command := fmt.Sprintf(`
		set -e
		export SUDO_PASS="%[1]s"

		echo "1. Настройка входа по паролю в SSH..."
		if %[2]t; then
			echo $SUDO_PASS | sudo -S sed -i 's/^#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
		else
			echo $SUDO_PASS | sudo -S sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
		fi

		echo "2. Настройка TCP форвардинга в SSH..."
		if %[3]t; then
			echo $SUDO_PASS | sudo -S sed -i 's/^#AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^#AllowTcpForwarding yes/AllowTcpForwarding yes/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
		else
			echo $SUDO_PASS | sudo -S sed -i 's/^#AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
		fi

		echo "3. Настройка X11 форвардинга в SSH..."
		if %[4]t; then
			echo $SUDO_PASS | sudo -S sed -i 's/^#X11Forwarding no/X11Forwarding yes/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^#X11Forwarding yes/X11Forwarding yes/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^X11Forwarding no/X11Forwarding yes/' /etc/ssh/sshd_config
		else
			echo $SUDO_PASS | sudo -S sed -i 's/^#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
		fi

		echo "4. Настройка Agent форвардинга в SSH..."
		if %[5]t; then
			echo $SUDO_PASS | sudo -S sed -i 's/^#AllowAgentForwarding no/AllowAgentForwarding yes/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^#AllowAgentForwarding yes/AllowAgentForwarding yes/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^AllowAgentForwarding no/AllowAgentForwarding yes/' /etc/ssh/sshd_config
		else
			echo $SUDO_PASS | sudo -S sed -i 's/^#AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config
			echo $SUDO_PASS | sudo -S sed -i 's/^AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config
		fi
		
		echo $SUDO_PASS | sudo -S systemctl restart sshd
		
		echo "Настройка SSH выполнена успешно"
	`, adminPassword, enablePasswordAuth, enableTCPForwarding, enableX11Forwarding, enableAgentForwarding)

	var b bytes.Buffer
	session.Stdout = &b
	session.Stderr = &b

	if err := session.Run(command); err != nil {
		return fmt.Errorf("ошибка выполнения команды: %v\nВывод: %s", err, b.String())
	}

	return nil
}

func createUserAndCopyKey(ip, adminName, adminKey, adminPassword, userName, userKey string) error {

	signer, err := ssh.ParsePrivateKey([]byte(adminKey))
	if err != nil {
		return fmt.Errorf("ошибка парсинга приватного ключа админа: %w", err)
	}

	config := &ssh.ClientConfig{
		User: adminName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", ip), config)
	if err != nil {
		return fmt.Errorf("ошибка подключения к SSH: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ошибка создания сессии: %w", err)
	}
	defer session.Close()

	command := fmt.Sprintf(`
		set -e
		export SUDO_PASS="%[3]s"
		
		echo "1. Создание пользователя..."
		echo $SUDO_PASS | sudo -S useradd -m %[1]s 2>/dev/null || true
		
		echo "2. Добавление в группу wheel..."
		echo $SUDO_PASS | sudo -S usermod -aG wheel %[1]s
		
		echo "3. Создание SSH директории..."
		echo $SUDO_PASS | sudo -S mkdir -p /home/%[1]s/.ssh
		
		echo "4. Копирование SSH ключа..."
		echo '%[2]s' > /tmp/temp_key_%[1]s
		echo $SUDO_PASS | sudo -S cp /tmp/temp_key_%[1]s /home/%[1]s/.ssh/authorized_keys
		rm /tmp/temp_key_%[1]s
		
		echo "5. Установка прав доступа для SSH..."
		echo $SUDO_PASS | sudo -S chmod 700 /home/%[1]s/.ssh
		echo $SUDO_PASS | sudo -S chmod 600 /home/%[1]s/.ssh/authorized_keys
		echo $SUDO_PASS | sudo -S chown -R %[1]s:%[1]s /home/%[1]s/.ssh
		
		echo "6. Создание sudoers файла..."
		echo $SUDO_PASS | sudo -S bash -c 'echo "%[1]s ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/%[1]s'
		
		echo "7. Установка прав доступа для sudoers..."
		echo $SUDO_PASS | sudo -S chmod 440 /etc/sudoers.d/%[1]s
		
		echo "8. Проверка содержимого sudoers файла..."
		if ! echo $SUDO_PASS | sudo -S cat /etc/sudoers.d/%[1]s; then
			echo "ОШИБКА: Не удалось прочитать файл sudoers"
			exit 1
		fi
		
		echo "Все операции выполнены успешно"
	`, userName, userKey, adminPassword)

	var b bytes.Buffer
	session.Stdout = &b
	session.Stderr = &b

	if err := session.Run(command); err != nil {
		return fmt.Errorf("ошибка выполнения команды: %v\nВывод: %s", err, b.String())
	}

	return nil
}

// Добавьте новую функцию для удаления пользователя
func removeUser(ip, adminName, adminKey, adminPassword, userName string) error {
	signer, err := ssh.ParsePrivateKey([]byte(adminKey))
	if err != nil {
		return fmt.Errorf("ошибка парсинга приватного ключа админа: %w", err)
	}

	config := &ssh.ClientConfig{
		User: adminName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", ip), config)
	if err != nil {
		return fmt.Errorf("ошибка подключения к SSH: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ошибка создания сессии: %w", err)
	}
	defer session.Close()

	command := fmt.Sprintf(`
		set -e
		export SUDO_PASS="%[2]s"
		
		echo "1. Удаление пользователя..."
		if id "%[1]s" >/dev/null 2>&1; then
			echo $SUDO_PASS | sudo -S userdel -r %[1]s
			echo "Пользователь %[1]s успешно удален"
		else
			echo "Пользователь %[1]s не существует"
		fi
		
		echo "2. Удаление файла sudoers..."
		if [ -f "/etc/sudoers.d/%[1]s" ]; then
			echo $SUDO_PASS | sudo -S rm /etc/sudoers.d/%[1]s
			echo "Файл sudoers для %[1]s удален"
		fi
	`, userName, adminPassword)

	var b bytes.Buffer
	session.Stdout = &b
	session.Stderr = &b

	if err := session.Run(command); err != nil {
		return fmt.Errorf("ошибка выполнения команды: %v\nВывод: %s", err, b.String())
	}

	return nil
}
