package database

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

type databaseStructure struct {
	Chirps map[int]chirp `json:"chirps"`
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

var id = 1

func (db database) CreateChirp(body string) (chirp, error) {
	c := chirp{
		Id:   id,
		Body: body,
	}
	dbs, err := db.load()
	if err != nil {
		return chirp{}, err
	}
	dbs.Chirps[id] = c
	id++
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

func NewDatabase(path string) (database, error) {
	fPath := filepath.Join(path, "database.json")
	file, err := os.Create(fPath)
	if err != nil {
		return database{}, err
	}
	defer file.Close()
	dbs, err := json.Marshal(databaseStructure{
		Chirps: map[int]chirp{},
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
