package database

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

type user struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
}

type databaseStructure struct {
	Chirps map[int]chirp   `json:"chirps"`
	Users  map[string]user `json:"users"`
}

type database struct {
	path string
	mu   *sync.RWMutex
}

func (db database) load() (databaseStructure, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	data, err := os.ReadFile(db.path)
	if err != nil {
		return databaseStructure{}, err
	}
	dbs := databaseStructure{}
	err = json.Unmarshal(data, &dbs)
	if err != nil {
		return databaseStructure{}, err
	}
	return dbs, nil
}

func (db database) save(dbs databaseStructure) error {
	data, err := json.Marshal(dbs)
	if err != nil {
		return err
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	err = os.WriteFile(db.path, data, 0666)
	if err != nil {
		return err
	}
	return nil
}

var chirpId = 1

func (db database) CreateChirp(body string) (chirp, error) {
	c := chirp{
		Id:   chirpId,
		Body: body,
	}
	dbs, err := db.load()
	if err != nil {
		return chirp{}, err
	}
	dbs.Chirps[chirpId] = c
	chirpId++
	err = db.save(dbs)
	if err != nil {
		return chirp{}, err
	}
	return c, nil
}

func (db database) GetChirps() ([]chirp, error) {
	dbs, err := db.load()
	if err != nil {
		return []chirp{}, err
	}
	chirps := make([]chirp, 0, len(dbs.Chirps))
	for _, c := range dbs.Chirps {
		chirps = append(chirps, c)
	}
	return chirps, nil
}

func (db database) GetChirp(chirpId int) (chirp, bool, error) {
	dbs, err := db.load()
	if err != nil {
		return chirp{}, false, err
	}
	c, ok := dbs.Chirps[chirpId]
	if !ok {
		return chirp{}, false, nil
	}
	return c, ok, nil
}

var userId = 1

func (db database) CreateUser(email, password string) (user, error) {
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return user{}, err
	}
	u := user{
		Id:       userId,
		Email:    email,
		Password: string(hashedPassword),
	}
	dbs, err := db.load()
	if err != nil {
		return user{}, err
	}
	dbs.Users[email] = u
	userId++
	err = db.save(dbs)
	if err != nil {
		return user{}, err
	}
	u.Password = ""
	return u, nil
}

func (db database) GetUser(userEmail string) (user, bool, error) {
	dbs, err := db.load()
	if err != nil {
		return user{}, false, err
	}
	u, ok := dbs.Users[userEmail]
	if !ok {
		return user{}, false, nil
	}
	return u, ok, nil
}

func (db *database) UpdateUser(keyEmail, newEmail, newPassword string) (user, error) {
	dbs, err := db.load()
	if err != nil {
		return user{}, err
	}
	u := dbs.Users[keyEmail]
	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		return user{}, err
	}
	newUser := user{
		Id:       u.Id,
		Email:    newEmail,
		Password: hashedPassword,
	}
	delete(dbs.Users, keyEmail)
	dbs.Users[newEmail] = newUser
	db.save(dbs)
	newUser.Password = "" // remove password filed from response
	return newUser, nil
}

func NewDatabase(path string) (database, error) {
	fPath := filepath.Join(path, "database.json")
	file, err := os.Create(fPath)
	if err != nil {
		return database{}, err
	}
	defer file.Close()
	dbs, err := json.Marshal(databaseStructure{
		Chirps: map[int]chirp{},
		Users:  map[string]user{},
	})
	if err != nil {
		return database{}, err
	}
	file.Write(dbs)
	err = file.Sync()
	if err != nil {
		return database{}, err
	}
	return database{
		path: fPath,
		mu:   &sync.RWMutex{},
	}, nil
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
