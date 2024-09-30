package cryptography

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/lib/pq"
)

const (
	Prefix      = "lkp"
	TokenLength = 10
	Base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

type Config struct {
	DBHost     string `json:"db_host"`
	DBPort     int    `json:"db_port"`
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	DBName     string `json:"db_name"`
}

func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

type TokenManager struct {
	db *sql.DB
	mu sync.Mutex
}

func NewTokenManager(db *sql.DB) *TokenManager {
	return &TokenManager{db: db}
}

func GenerateRandomToken(length int) (string, error) {
	numBytes := 6
	randomBytes := make([]byte, numBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	var number uint64
	for i := 0; i < numBytes; i++ {
		number = (number << 8) | uint64(randomBytes[i])
	}

	token := ""
	for i := 0; i < length; i++ {
		remainder := number % 62
		token = string(Base62Chars[remainder]) + token
		number = number / 62
	}

	return token, nil
}

func (tm *TokenManager) GetOrCreateServiceToken(serviceName string) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	var token string

	err := tm.db.QueryRow("SELECT token FROM service_tokens WHERE service_name = $1", serviceName).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			for {
				tk, err := GenerateRandomToken(TokenLength)
				if err != nil {
					return "", err
				}

				_, err = tm.db.Exec("INSERT INTO service_tokens (token, service_name) VALUES ($1, $2)", tk, serviceName)
				if err != nil {
					if isUniqueViolation(err) {
						continue
					}
					return "", err
				}
				token = tk
				break
			}
		} else {
			return "", err
		}
	}

	return token, nil
}

func (tm *TokenManager) GetOrCreateUserToken(userName string) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	var token string

	err := tm.db.QueryRow("SELECT token FROM user_tokens WHERE user_name = $1", userName).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			for {
				tk, err := GenerateRandomToken(TokenLength)
				if err != nil {
					return "", err
				}

				_, err = tm.db.Exec("INSERT INTO user_tokens (token, user_name) VALUES ($1, $2)", tk, userName)
				if err != nil {
					if isUniqueViolation(err) {
						continue
					}
					return "", err
				}
				token = tk
				break
			}
		} else {
			return "", err
		}
	}

	return token, nil
}

func isUniqueViolation(err error) bool {
	pqErr, ok := err.(*pq.Error)
	if !ok {
		return false
	}
	return pqErr.Code == "23505"
}

func Crypto(serviceName string, userName string) string {

	config, err := LoadConfig("configs/database_config.json")
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.DBHost, config.DBPort, config.DBUser, config.DBPassword, config.DBName)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Ошибка подключения к базе данных: %v", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}

	tokenManager := NewTokenManager(db)

	serviceToken, err := tokenManager.GetOrCreateServiceToken(serviceName)
	if err != nil {
		log.Fatalf("Ошибка генерации токена сервиса: %v", err)
	}

	userToken, err := tokenManager.GetOrCreateUserToken(userName)
	if err != nil {
		log.Fatalf("Ошибка генерации токена пользователя: %v", err)
	}

	key := fmt.Sprintf("%s-%s-%s", Prefix, serviceToken, userToken)
	return key
}
