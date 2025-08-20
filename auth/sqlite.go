package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/cameronmore/go-sessions/sessions"
)

type SQLiteAuthStore struct {
	DB     *sql.DB
	Secret string
	Duration time.Duration
}

// Returns a new SQLite AuthStore and creates the necessary user and sessions tables if they don't exist
func NewSQLiteStore(db *sql.DB, secret string, d time.Duration) (*SQLiteAuthStore, error) {

	// set up session table
	newSessionTableQuery := `
	CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL
	);
	`
	_, err := db.Exec(newSessionTableQuery)
	if err != nil {
		return nil, err
	}

	// set up session table
	newUserTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
	user_id TEXT PRIMARY KEY,
	hashed_password TEXT NOT NULL
	);
	`
	_, err = db.Exec(newUserTableQuery)
	if err != nil {
		return nil, err
	}

	return &SQLiteAuthStore{
		DB:     db,
		Secret: secret,
		Duration: d,
	}, nil
}

func (s *SQLiteAuthStore) SaveUser(u sessions.User) error {
	existingUser, err := s.LoadUserByUserId(u.UserId, context.Background())
	if existingUser.HashedPassword != "" {
		return errors.New("User already exists, cannot save user")
	}
	newUserQuery := `
		INSERT INTO users (user_id, hashed_password)
		VALUES (?, ?)
		`
	_, err = s.DB.Exec(newUserQuery, u.UserId, u.HashedPassword)
	if err != nil {
		return err
	}
	return nil
}

func (s *SQLiteAuthStore) LoadUserByUserId(id string, ctx context.Context) (sessions.User, error) {
	var u sessions.User
	u.UserId = id
	var storedHashedPassword string
	err := s.DB.QueryRowContext(ctx, "SELECT hashed_password FROM users WHERE user_id = ?", id).Scan(&storedHashedPassword)
	if err != nil {
		return u, err
	}
	u.HashedPassword = storedHashedPassword
	return u, nil
}

func (s *SQLiteAuthStore) SaveSession(session sessions.Session) error {
	newSessionQuery := `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES (?, ?, ?)
		`
	_, err := s.DB.Exec(newSessionQuery, session.Id, session.UserId, session.ExpiresAt)
	if err != nil {
		return err
	}
	return nil
}

func (s *SQLiteAuthStore) DeleteSessionById(id string) error {

	deleteSessionQuery := `
	DELETE FROM sessions
	WHERE id = ?
	`
	result, err := s.DB.Exec(deleteSessionQuery, id)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return errors.New("Session not found")
	}
	return nil
}

func (s *SQLiteAuthStore) LoadSessionById(id string, ctx context.Context) (sessions.Session, error) {
	var session sessions.Session
	session.Id = sessions.SessionId(id)
	var storedUserID string
	var expiresAt time.Time
	query := `SELECT user_id, expires_at FROM sessions WHERE id = ?`
	err := s.DB.QueryRowContext(ctx, query, id).Scan(&storedUserID, &expiresAt)
	session.ExpiresAt = expiresAt
	session.UserId = storedUserID
	return session, err
}

func (s *SQLiteAuthStore) YieldKey() string {
	return s.Secret
}

func (s *SQLiteAuthStore) YieldDuration() time.Duration {
	return s.Duration
}