### Конфигурация
#### Создайте в корне проекта файл `config.yaml` с содержимым:
```yaml
# Данные адмиской учетки через которую будет происходить копирование ключей, учетная запись админа предварительно должна быть создана на всех vm
# По завершению доступ vm будет только через ssh ключ
certs_admin:
  - name: admin
    key: "ssh-rsa AAAAB3NzaC1KYOFhDptpKcvX8zv4XIrnwKtFlsLmP6/+yrHeIHJMnTbUzruNotR test.ru"
    password: "xxxx"
    private_key: |
      -----BEGIN RSA PRIVATE KEY-----
      MIIEpAIBAAKCAQEAoULIvhT0Du/81/epm6mrpZ9wi6gKdt2ppP7PVMu06xCo8Bef
      3+7JkY/vvU3UjHQ3UAGkchmtXdY4fkjD+eH+o/WZAHy9wXghQUPAvO2SRJ6dN7Sk
      ISomcUBHYqoTi800q99oGDpvCRwr7RLUE5ShR/sCgYEAuw+v9KaZhFZehDabjv9J
      95e+vRzQiMqMW0V7UiazfAjY0u1lALRd6svFTJmuS3zViWA2oTBBXA4lzRfPyxxd
      wQS7c/trphOVRuCYMyKxebKAxtqTSUsncoFhJuGKsruPY6pMr40/lsehYh44G6KS
      8CVnIJiFHq5PdXB8HCADGDsCgYEAiNJpiouayd4slo2KqcVHU3JDuf3CNxrPIbXy
      CqEOZjFYueJ+Lt38z2vxFfe2+eRk1r4MuAQny3tykBE8IpXcQWhmyFp+XxSCR7RL
      GsWx9R8W4dj+dESEaM2qAW37FIwIhS2kUhi3bCC0KTVW/61X5ZxEYI0Jm4lVCHWz
      IPgbhfECgYAwt2PYHl6hbQ+iQwd3bQWyGZGbREt79Dyo4+uaz+yVK8vm/plproVN
      zfojMeIHH0qHwcQJOfMLwKvVJX3vQMEmr8EN7SHSFjxJH9QG7DwWYn+fm9y+Ym2T
      jbtXDxuqGk22lG3/w038wdDGOCb4J75qLPqw/6kqW5nYgUdv42sQPw==
      -----END RSA PRIVATE KEY-----

# Данные пользователей которые будут созданы на vm (пара login - публичный ключ)
users:
  - name: username
    key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKAcYo7SsdVbtQFLWR5rygsZPF+VB test@test.ru"

# IP адреса на которые будет происходить копирование ключей
ip:
  - 192.168.1.1
  - 192.168.1.2

# Пользователи которые будут удалены с vm
remove_users:
  - name: username

# IP адреса на которых будет происходить удаление пользователей
remove_users_ip:
  - 192.168.41.38

# Настройка входа по паролю в SSH
auth_password:
  enable: false
```
