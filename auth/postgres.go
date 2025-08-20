package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/cameronmore/go-sessions/sessions"
)

type PostgresAuthStore struct {
	DB *sql.DB
}

// Returns a new SQLite AuthStore and creates the necessary user and sessions tables if they don't exist
func NewPostgresAuthStore(db *sql.DB) (*PostgresAuthStore, error) {

	// set up session table
	newSessionTableQuery := `
	CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	expires_at BIGINT NOT NULL -- Unix timestamp (seconds)
	);
	`
	_, err := db.Exec(newSessionTableQuery)
	if err != nil {
		return nil, err
	}

	// set up session table
	newUserTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
	user_id TEXT PRIMARY KEY NOT NULL,
	username TEXT NOT NULL UNIQUE,
	hashed_password TEXT NOT NULL
	);
	`
	_, err = db.Exec(newUserTableQuery)
	if err != nil {
		return nil, err
	}

	return &PostgresAuthStore{
		DB: db,
	}, nil
}

// save a user with the Postgres store
func (pg *PostgresAuthStore) SaveUser(u sessions.User) error {
	existingUser, err := pg.LoadUserByUserId(u.UserId, context.Background())
	if !errors.Is(err, sessions.ErrUserNotFound) {
		return err
	}
	if existingUser.HashedPassword != "" {
		return errors.New("User already exists, cannot save user")
	}
	newUserQuery := `
		INSERT INTO users (user_id, hashed_password, username)
		VALUES ($1, $2, $3)
		`
	_, err = pg.DB.Exec(newUserQuery, u.UserId, u.HashedPassword, u.Username)
	if err != nil {
		return err
	}
	return nil
}

// Load user in Postgres store
func (pg *PostgresAuthStore) LoadUserByUserId(id string, ctx context.Context) (sessions.User, error) {
	var u sessions.User
	u.UserId = id
	err := pg.DB.QueryRowContext(ctx, "SELECT hashed_password, username FROM users WHERE user_id = $1", id).Scan(&u.HashedPassword, &u.Username)
	if errors.Is(sql.ErrNoRows, err) {
		return u, sessions.ErrUserNotFound
	} else if err != nil {
		return u, err
	}
	return u, nil
}

// Load user in Postgres store
func (pg *PostgresAuthStore) LoadUserByUsername(username string, ctx context.Context) (sessions.User, error) {
	var u sessions.User
	u.Username = username
	err := pg.DB.QueryRowContext(ctx, "SELECT hashed_password, user_id FROM users WHERE username = $1", username).Scan(&u.HashedPassword, &u.UserId)
	if errors.Is(sql.ErrNoRows, err) {
		return u, sessions.ErrUserNotFound
	} else if err != nil {
		return u, err
	}
	return u, nil
}

// Save session in Postgres store
func (pg *PostgresAuthStore) SaveSession(session sessions.Session) error {
	newSessionQuery := `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES ($1, $2, $3)
		`
	_, err := pg.DB.Exec(newSessionQuery, session.Id, session.UserId, session.ExpiresAt.Unix())
	if err != nil {
		return err
	}
	return nil
}

// Delete session in Postgres store
func (pg *PostgresAuthStore) DeleteSessionById(id string) error {

	deleteSessionQuery := `
	DELETE FROM sessions
	WHERE id = $1
	`
	result, err := pg.DB.Exec(deleteSessionQuery, id)
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

// Load session in Postgres store
func (pg *PostgresAuthStore) LoadSessionById(id string, ctx context.Context) (sessions.Session, error) {
	var session sessions.Session
	session.Id = sessions.SessionId(id)
	var storedUserID string
	// var expiresAt time.Time
	var expiresAtUnix int64
	query := `SELECT user_id, expires_at FROM sessions WHERE id = $1`
	err := pg.DB.QueryRowContext(ctx, query, id).Scan(&storedUserID, &expiresAtUnix)
	if errors.Is(sql.ErrNoRows, err) {
		return session, sessions.ErrSessionNotFound
	}
	session.ExpiresAt = time.Unix(expiresAtUnix, 0)
	session.UserId = storedUserID
	return session, err
}
