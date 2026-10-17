package services

import (
	"context"
	"errors"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var (
	ErrSecretKindInvalid            = errors.New("kind must be password or private_key")
	ErrSecretMissingUsernameOrValue = errors.New("username and value are required")
	ErrSecretKindRequiredWithValue  = errors.New("kind is required when replacing the value")
	ErrSecretValueEmpty             = errors.New("value must not be empty")
	ErrSecretKindRequiresValue      = errors.New("kind can only change together with value")
)

type SecretVault interface {
	Seal(plaintext, aad []byte) []byte
	Open(sealed, aad []byte) ([]byte, error)
}

type CreateSecretParams struct {
	Name     string
	Kind     string
	Username string
	Value    string
	Actor    store.Actor
}

type UpdateSecretParams struct {
	ID       string
	Name     *string
	Username *string
	Kind     *string
	Value    *string
	Actor    store.Actor
}

type SecretService struct {
	store *store.Store
	vault SecretVault
}

func NewSecretService(st *store.Store, v SecretVault) *SecretService {
	return &SecretService{store: st, vault: v}
}

func (s *SecretService) List(ctx context.Context) ([]db.ListSecretsRow, error) {
	return s.store.Q.ListSecrets(ctx)
}

func (s *SecretService) Get(ctx context.Context, id string) (db.ConfigSecret, error) {
	sec, err := s.store.Q.GetSecret(ctx, id)
	if err != nil {
		return db.ConfigSecret{}, store.Classify(err)
	}
	return sec, nil
}

func (s *SecretService) GetByName(ctx context.Context, name string) (db.ConfigSecret, error) {
	sec, err := s.store.Q.GetSecretByName(ctx, name)
	if err != nil {
		return db.ConfigSecret{}, store.Classify(err)
	}
	return sec, nil
}

func validateSecretKind(k string) error {
	if k != "password" && k != "private_key" {
		return ErrSecretKindInvalid
	}
	return nil
}

func (s *SecretService) Create(ctx context.Context, params CreateSecretParams) (db.ConfigSecret, error) {
	if err := validateName(params.Name); err != nil {
		return db.ConfigSecret{}, err
	}
	if err := validateSecretKind(params.Kind); err != nil {
		return db.ConfigSecret{}, err
	}
	if params.Username == "" || params.Value == "" {
		return db.ConfigSecret{}, ErrSecretMissingUsernameOrValue
	}
	if s.vault == nil {
		return db.ConfigSecret{}, errors.New("secret vault not initialized")
	}

	id := store.NewID()
	var created db.ConfigSecret

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		sealed := s.vault.Seal([]byte(params.Value), []byte(id))
		if err := q.CreateSecret(ctx, db.CreateSecretParams{
			ID:       id,
			Name:     params.Name,
			Kind:     params.Kind,
			Username: params.Username,
			Sealed:   sealed,
			Now:      store.Now(),
		}); err != nil {
			return store.Classify(err)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "secret.create",
			ObjectType: "secret",
			ObjectID:   id,
			Details: map[string]any{
				"name":     params.Name,
				"kind":     params.Kind,
				"username": params.Username,
			},
		}); err != nil {
			return err
		}

		var err error
		created, err = q.GetSecret(ctx, id)
		return err
	})
	if err != nil {
		return db.ConfigSecret{}, err
	}
	return created, nil
}

func (s *SecretService) Update(ctx context.Context, params UpdateSecretParams) (db.ConfigSecret, error) {
	var out db.ConfigSecret
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		sec, err := q.GetSecret(ctx, params.ID)
		if err != nil {
			return store.Classify(err)
		}

		details := map[string]any{}
		if params.Name != nil || params.Username != nil {
			if params.Name != nil {
				if err := validateName(*params.Name); err != nil {
					return err
				}
				sec.Name = *params.Name
				details["name"] = sec.Name
			}
			if params.Username != nil {
				sec.Username = *params.Username
				details["username"] = sec.Username
			}
			if err := q.UpdateSecretMeta(ctx, db.UpdateSecretMetaParams{
				ID:       params.ID,
				Name:     sec.Name,
				Username: sec.Username,
				Now:      store.Now(),
			}); err != nil {
				return store.Classify(err)
			}
		}

		if params.Value != nil {
			if params.Kind == nil {
				return ErrSecretKindRequiredWithValue
			}
			if err := validateSecretKind(*params.Kind); err != nil {
				return err
			}
			if *params.Value == "" {
				return ErrSecretValueEmpty
			}
			if s.vault == nil {
				return errors.New("secret vault not initialized")
			}
			sealed := s.vault.Seal([]byte(*params.Value), []byte(params.ID))
			if err := q.UpdateSecretValue(ctx, db.UpdateSecretValueParams{
				ID:     params.ID,
				Kind:   *params.Kind,
				Sealed: sealed,
				Now:    store.Now(),
			}); err != nil {
				return err
			}
			details["value_replaced"] = true
			details["kind"] = *params.Kind
		} else if params.Kind != nil {
			return ErrSecretKindRequiresValue
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "secret.update",
			ObjectType: "secret",
			ObjectID:   params.ID,
			Details:    details,
		}); err != nil {
			return err
		}

		out, err = q.GetSecret(ctx, params.ID)
		return err
	})
	if err != nil {
		return db.ConfigSecret{}, err
	}
	return out, nil
}

func (s *SecretService) Delete(ctx context.Context, actor store.Actor, id string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		sec, err := q.GetSecret(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if _, err := q.DeleteSecret(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "secret.delete",
			ObjectType: "secret",
			ObjectID:   id,
			Details:    map[string]any{"name": sec.Name},
		})
	})
}

func (s *SecretService) DeleteByName(ctx context.Context, actor store.Actor, name string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		sec, err := q.GetSecretByName(ctx, name)
		if err != nil {
			return store.Classify(err)
		}
		n, err := q.DeleteSecret(ctx, sec.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrNotFound
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "secret.delete",
			ObjectType: "secret",
			ObjectID:   sec.ID,
			Details:    map[string]any{"name": name},
		})
	})
}
