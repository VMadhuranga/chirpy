package database

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId int    `json:"author_id"`
}

type user struct {
	Id              int        `json:"id"`
	Email           string     `json:"email"`
	IsChirpyRed     bool       `json:"is_chirpy_red"`
	Password        string     `json:"password,omitempty"`
	Token           string     `json:"token,omitempty"`
	RefreshToken    string     `json:"refresh_token,omitempty"`
	RefreshTokenExp *time.Time `json:"refresh_token_exp,omitempty"`
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

func (db database) CreateChirp(body string, authorId int) (chirp, error) {
	c := chirp{
		Id:       chirpId,
		Body:     body,
		AuthorId: authorId,
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

func (db database) GetChirps(sortOrder string) ([]chirp, error) {
	dbs, err := db.load()
	if err != nil {
		return []chirp{}, err
	}
	chirps := make([]chirp, 0, len(dbs.Chirps))
	for _, c := range dbs.Chirps {
		chirps = append(chirps, c)
	}
	return sortChirps(chirps, sortOrder), nil
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

func (db database) GetAuthorChirps(authorId int, sortOrder string) ([]chirp, error) {
	dbs, err := db.load()
	if err != nil {
		return []chirp{}, err
	}
	authorChirps := []chirp{}
	for _, chirp := range dbs.Chirps {
		if chirp.AuthorId == authorId {
			authorChirps = append(authorChirps, chirp)
		}
	}
	return sortChirps(authorChirps, sortOrder), nil
}

func (db database) DeleteChirp(chirpId int) error {
	dbs, err := db.load()
	if err != nil {
		return err
	}
	delete(dbs.Chirps, chirpId)
	err = db.save(dbs)
	if err != nil {
		return err
	}
	return nil
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
		Id:              u.Id,
		Email:           newEmail,
		Password:        hashedPassword,
		Token:           u.Token,
		RefreshToken:    u.RefreshToken,
		RefreshTokenExp: u.RefreshTokenExp,
	}
	delete(dbs.Users, keyEmail)
	dbs.Users[newEmail] = newUser
	db.save(dbs)
	newUser.Password = ""         // remove password field from response
	newUser.RefreshToken = ""     // remove refresh token field from response
	newUser.RefreshTokenExp = nil // remove refresh token exp field from response
	return newUser, nil
}

func (db database) CreateRefreshToken(keyEmail string) (string, error) {
	dbs, err := db.load()
	if err != nil {
		return "", err
	}
	refreshToken := make([]byte, 32)
	_, err = rand.Read(refreshToken)
	if err != nil {
		return "", err
	}
	u := dbs.Users[keyEmail]
	refreshTokenExp := time.Now().Add(60 * 24 * time.Hour)
	dbs.Users[keyEmail] = user{
		Id:              u.Id,
		Email:           u.Email,
		Password:        u.Password,
		IsChirpyRed:     u.IsChirpyRed,
		Token:           u.Token,
		RefreshToken:    hex.EncodeToString(refreshToken),
		RefreshTokenExp: &refreshTokenExp,
	}
	err = db.save(dbs)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(refreshToken), nil
}

func (db database) GetRefreshTokenUser(refreshToken string) (user, error) {
	dbs, err := db.load()
	if err != nil {
		return user{}, err
	}
	for _, u := range dbs.Users {
		if u.RefreshToken == refreshToken {
			return u, nil
		}
	}
	return user{}, nil
}

func (db *database) RevokeUserRefreshToken(refreshToken string) error {
	dbs, err := db.load()
	if err != nil {
		return err
	}
	for _, u := range dbs.Users {
		if u.RefreshToken == refreshToken {
			dbs.Users[u.Email] = user{
				Id:              u.Id,
				Email:           u.Email,
				Password:        u.Password,
				Token:           u.Token,
				RefreshToken:    "",
				RefreshTokenExp: nil,
			}
			break
		}
	}
	err = db.save(dbs)
	if err != nil {
		return err
	}
	return nil
}

func (db database) UpdateUserChirpyRedStatus(userEmail string) (bool, error) {
	dbs, err := db.load()
	if err != nil {
		return false, err
	}
	u, ok := dbs.Users[userEmail]
	if !ok {
		return false, nil
	}
	dbs.Users[userEmail] = user{
		Id:              u.Id,
		Email:           u.Email,
		IsChirpyRed:     true,
		Password:        u.Password,
		Token:           u.Token,
		RefreshToken:    u.RefreshToken,
		RefreshTokenExp: u.RefreshTokenExp,
	}
	err = db.save(dbs)
	if err != nil {
		return false, err
	}
	return true, nil
}

func sortChirps(chirps []chirp, sortOrder string) []chirp {
	if sortOrder == "" || sortOrder == "asc" {
		slices.SortFunc(chirps, func(a, b chirp) int {
			return a.Id - b.Id
		})
	} else if sortOrder == "desc" {
		slices.SortFunc(chirps, func(a, b chirp) int {
			return b.Id - a.Id
		})
	}
	return chirps
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
