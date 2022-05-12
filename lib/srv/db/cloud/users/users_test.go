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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	libaws "github.com/gravitational/teleport/lib/cloud/aws"
	"github.com/gravitational/teleport/lib/defaults"
	libsecrets "github.com/gravitational/teleport/lib/secrets"
	"github.com/gravitational/teleport/lib/srv/db/cloud"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/trace"
)

func TestUsers(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	managedTags := map[string]string{
		"env":                        "test",
		libaws.TagKeyTeleportManaged: libaws.TagValueTrue,
	}

	clock := clockwork.NewFakeClock()
	smMock := libsecrets.NewMockSecretsManagerClient(libsecrets.MockSecretsManagerClientConfig{
		Clock: clock,
	})
	ecMock := &cloud.ElastiCacheMock{}
	ecMock.AddMockUser(elastiCacheUser("alice", "group1"), managedTags)
	ecMock.AddMockUser(elastiCacheUser("bob", "group1", "group2"), managedTags)
	ecMock.AddMockUser(elastiCacheUser("charlie", "group2", "group3"), managedTags)
	ecMock.AddMockUser(elastiCacheUser("dan", "group3"), managedTags)
	ecMock.AddMockUser(elastiCacheUser("not-managed", "group1", "group2"), nil)

	db1 := mustCreateElastiCacheDatabase(t, "db1", "group1")
	db2 := mustCreateElastiCacheDatabase(t, "db2", "group2")
	db3 := mustCreateElastiCacheDatabase(t, "db3", "group-not-found")
	db4 := mustCreateElastiCacheDatabase(t, "db4" /*no group*/)
	db5 := mustCreateRDSDatabase(t, "db5")

	users, err := NewUsers(Config{
		Clients: &common.TestCloudClients{
			ElastiCache:    ecMock,
			SecretsManager: smMock,
		},
		Clock: clock,
	})
	require.NoError(t, err)

	t.Run("SetupDatabse", func(t *testing.T) {
		for _, database := range []types.Database{db1, db2, db3, db4, db5} {
			require.NoError(t, users.SetupDatabase(ctx, database))
		}

		requireDatabaseWithManagedUsers(t, users, db1, []string{"alice", "bob"})
		requireDatabaseWithManagedUsers(t, users, db2, []string{"bob", "charlie"})
		require.Empty(t, db3.GetManagedUsers())
		require.Empty(t, db4.GetManagedUsers())
		require.Empty(t, db5.GetManagedUsers())
	})

	t.Run("setupAllDatabases", func(t *testing.T) {
		// Update db1 to group3.
		db1Meta := db1.GetAWS()
		db1Meta.ElastiCache.UserGroupIDs = []string{"group3"}
		db1.SetStatusAWS(db1Meta)

		// Remove db2.
		clock.Advance(time.Hour)
		users.setupAllDatabases(ctx, types.Databases{db1, db3, db4, db5})

		// Validate db1 is updated.
		requireDatabaseWithManagedUsers(t, users, db1, []string{"charlie", "dan"})

		// Validate db2 is no longer tracked.
		_, err = users.GetPassword(ctx, db2, "charlie")
		require.True(t, trace.IsNotFound(err))
	})
}

func requireDatabaseWithManagedUsers(t *testing.T, users *Users, db types.Database, managedUsers []string) {
	require.Equal(t, managedUsers, db.GetManagedUsers())
	for _, username := range managedUsers {
		password, err := users.GetPassword(context.TODO(), db, username)
		require.NoError(t, err)
		require.NotEmpty(t, password)
	}
}

func mustCreateElastiCacheDatabase(t *testing.T, name string, userGroupIDs ...string) types.Database {
	db, err := types.NewDatabaseV3(types.Metadata{
		Name: name,
	}, types.DatabaseSpecV3{
		Protocol: defaults.ProtocolRedis,
		URI:      "master.redis-cluster.1234567890.use1.cache.amazonaws.com:6379",
		AWS: types.AWS{
			ElastiCache: types.ElastiCache{
				UserGroupIDs: userGroupIDs,
			},
		},
	})
	require.NoError(t, err)
	return db
}

func mustCreateRDSDatabase(t *testing.T, name string) types.Database {
	db, err := types.NewDatabaseV3(types.Metadata{
		Name: name,
	}, types.DatabaseSpecV3{
		Protocol: defaults.ProtocolMySQL,
		URI:      "aurora-instance-1.abcdefghijklmnop.us-west-1.rds.amazonaws.com:5432",
	})
	require.NoError(t, err)
	return db
}

func elastiCacheUser(name string, groupIDs ...string) *elasticache.User {
	return &elasticache.User{
		UserId:       aws.String(name),
		ARN:          aws.String("arn:aws:elasticache:us-east-1:1234567890:user:" + name),
		UserName:     aws.String(name),
		UserGroupIds: aws.StringSlice(groupIDs),
	}
}
