///////////////////////////////////////////////////////////////////////////
//
// Copyright 2021 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#ifndef REALM_NOINST_CLIENT_RESET_HPP
#define REALM_NOINST_CLIENT_RESET_HPP

#include <realm/util/logger.hpp>
#include <realm/util/optional.hpp>
#include <realm/sync/config.hpp>
#include <realm/sync/protocol.hpp>

#include <ostream>

namespace realm {

std::ostream& operator<<(std::ostream& os, const ClientResyncMode& mode);

namespace sync {
class SubscriptionStore;
}

namespace _impl::client_reset {

// The reset fails if there seems to be conflict between the
// instructions and state.
//
// After failure the processing stops and the client reset will
// drop all local changes.
//
// Failure is triggered by:
// 1. Destructive schema changes.
// 2. Creation of an already existing table with another type.
// 3. Creation of an already existing column with another type.
struct ClientResetFailed : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

// transfer_group() transfers all tables, columns, objects and values from the src
// group to the dst group and deletes everything in the dst group that is absent in
// the src group. An update is only performed when a comparison shows that a
// change is needed. In this way, the continuous transaction history of changes
// is minimal.
//
// The result is that src group is unchanged and the dst group is equal to src
// when this function returns.
void transfer_group(const Transaction& tr_src, Transaction& tr_dst, util::Logger& logger,
                    bool allow_schema_additions);

struct PendingReset {
    ClientResyncMode type;
    sync::ProtocolErrorInfo::Action action;
    Timestamp time;
};
void remove_pending_client_resets(Transaction& wt);
util::Optional<PendingReset> has_pending_reset(const Transaction& wt);
void track_reset(Transaction& wt, ClientResyncMode mode, sync::ProtocolErrorInfo::Action action);

// Exposed for testing only
int64_t from_reset_action(sync::ProtocolErrorInfo::Action action);
sync::ProtocolErrorInfo::Action to_reset_action(int64_t action);
ClientResyncMode to_resync_mode(int64_t mode);
int64_t from_resync_mode(ClientResyncMode mode);
ClientResyncMode reset_precheck_guard(Transaction& wt, ClientResyncMode mode, bool recovery_is_allowed,
                                      sync::ProtocolErrorInfo::Action action, util::Logger& logger);

// preform_client_reset_diff() takes the Realm performs a client reset on
// the Realm in 'path_local' given the Realm 'path_fresh' as the source of truth.
// If the fresh path is not provided, discard mode is assumed and all data in the local
// Realm is removed.
// If the fresh path is provided, the local Realm is changed such that its state is equal
// to the fresh Realm. Then the local Realm will have its client file ident set to
// 'client_file_ident'
bool perform_client_reset_diff(DB& db, DB& db_remote, sync::SaltedFileIdent client_file_ident, util::Logger& logger,
                               ClientResyncMode mode, bool recovery_is_allowed, sync::SubscriptionStore* sub_store,
                               sync::ProtocolErrorInfo::Action action,
                               util::FunctionRef<void(int64_t)> on_flx_version_complete);

} // namespace _impl::client_reset
} // namespace realm

#endif // REALM_NOINST_CLIENT_RESET_HPP
