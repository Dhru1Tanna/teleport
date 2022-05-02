/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package users

import (
	"context"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

func TestUsersMap(t *testing.T) {
	users := newUsersMap()
	user1 := newMockUser("userID1", "user1")
	user2 := newMockUser("userID2", "user2")

	t.Run("addUser", func(t *testing.T) {
		users.addUser(user1)
		users.addUser(user2)

		require.Equal(t, 2, users.len())
	})

	t.Run("findUser", func(t *testing.T) {
		for _, findUser := range []User{user1, user2} {
			user, found := users.findUser(findUser.GetID())
			require.True(t, found)
			require.Equal(t, findUser.GetInDatabaseName(), user.GetInDatabaseName())
		}
	})

	t.Run("findUser not found", func(t *testing.T) {
		_, found := users.findUser("userID999")
		require.False(t, found)
	})

	t.Run("removeUnused", func(t *testing.T) {
		activeUsers := map[string]User{
			user1.GetID(): user1,
		}

		removed := users.removeUnused(activeUsers)
		require.Equal(t, []User{user2}, removed)
		require.Equal(t, 1, users.len())

		_, found := users.findUser(user1.GetID())
		require.True(t, found)
	})
}

func TestLookupMap(t *testing.T) {
	lookup := newLookupMap()
	db1 := mustCreateElastiCacheDatabase(t, "db1")
	db2 := mustCreateElastiCacheDatabase(t, "db2")
	db3 := mustCreateElastiCacheDatabase(t, "db3")
	user1 := newMockUser("userID1", "user1")
	user2 := newMockUser("userID2", "user2")
	user3 := newMockUser("userID3", "user3")

	t.Run("setDatabaseUsers", func(t *testing.T) {
		lookup.setDatabaseUsers(db1, []User{user1, user2}, true)
		lookup.setDatabaseUsers(db2, []User{}, true)

		require.Equal(t, []string{"user1", "user2"}, db1.GetManagedUsers())
		require.Len(t, db2.GetManagedUsers(), 0)
	})

	t.Run("getDatabaseUser", func(t *testing.T) {
		user, found := lookup.getDatabaseUser(db1, "user1")
		require.True(t, found)
		require.Equal(t, user1, user)

		_, found = lookup.getDatabaseUser(db1, "user999")
		require.False(t, found)

		_, found = lookup.getDatabaseUser(db2, "user1")
		require.False(t, found)
	})

	t.Run("usersByID", func(t *testing.T) {
		require.Equal(t, map[string]User{
			"userID1": user1,
			"userID2": user2,
		}, lookup.usersByID())
	})

	t.Run("swap", func(t *testing.T) {
		other := newLookupMap()
		other.setDatabaseUsers(db3, []User{user3}, false)

		lookup.swap(other, true)

		require.Equal(t, map[string]User{"userID3": user3}, lookup.usersByID())
		require.Equal(t, []string{"user3"}, db3.GetManagedUsers())
	})
}

func TestGenRandomPassword(t *testing.T) {
	for _, test := range []struct {
		name        string
		inputLength int
		expectError bool
	}{
		{
			name:        "even",
			inputLength: 50,
		},
		{
			name:        "odd",
			inputLength: 51,
		},
		{
			name:        "invalid",
			inputLength: 0,
			expectError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			generated, err := genRandomPassword(test.inputLength)
			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Len(t, generated, test.inputLength)
			}
		})
	}
}

func TestSecretKeyFromAWSARN(t *testing.T) {
	_, err := secretKeyFromAWSARN("invalid:arn")
	require.True(t, trace.IsBadParameter(err))

	key, err := secretKeyFromAWSARN("arn:aws-cn:elasticache:cn-north-1:1234567890:user:alice")
	require.NoError(t, err)
	require.Equal(t, "elasticache/cn-north-1/1234567890/user/alice", key)
}

type mockUser struct {
	id             string
	inDatabaseName string
}

func newMockUser(id, inDatabaseName string) *mockUser {
	return &mockUser{
		id:             id,
		inDatabaseName: inDatabaseName,
	}
}

func (m *mockUser) GetID() string                                   { return m.id }
func (m *mockUser) GetInDatabaseName() string                       { return m.inDatabaseName }
func (m *mockUser) Setup(ctx context.Context) error                 { return nil }
func (m *mockUser) Teardown(ctx context.Context) error              { return nil }
func (m *mockUser) GetPassword(ctx context.Context) (string, error) { return "password", nil }
func (m *mockUser) RotatePassword(ctx context.Context) error        { return nil }
