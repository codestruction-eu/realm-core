// swift-tools-version:5.3

import PackageDescription
import Foundation

let versionStr = "11.7.0"
let versionPieces = versionStr.split(separator: "-")
let versionCompontents = versionPieces[0].split(separator: ".")
let versionExtra = versionPieces.count > 1 ? versionPieces[1] : ""

var cxxSettings: [CXXSetting] = [
    .headerSearchPath("."),
    .define("REALM_DEBUG", .when(configuration: .debug)),
    .define("REALM_NO_CONFIG"),
    .define("REALM_INSTALL_LIBEXECDIR", to: ""),
    .define("REALM_ENABLE_ASSERTIONS", to: "1"),
    .define("REALM_ENABLE_ENCRYPTION", to: "1"),
    .define("REALM_ENABLE_SYNC", to: "1"),

    .define("REALM_VERSION_MAJOR", to: String(versionCompontents[0])),
    .define("REALM_VERSION_MINOR", to: String(versionCompontents[1])),
    .define("REALM_VERSION_PATCH", to: String(versionCompontents[2])),
    .define("REALM_VERSION_EXTRA", to: "\"\(versionExtra)\""),
    .define("REALM_VERSION_STRING", to: "\"\(versionStr)\"")
]

#if swift(>=5.5)
cxxSettings.append(.define("REALM_HAVE_SECURE_TRANSPORT", to: "1", .when(platforms: [.macOS, .macCatalyst, .iOS, .tvOS, .watchOS])))
#else
cxxSettings.append(.define("REALM_HAVE_SECURE_TRANSPORT", to: "1", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS])))
#endif

let syncServerSources: [String] =  [
    "realm/sync/noinst/server",
]

let syncExcludes: [String] = [
    // Server files
    "realm/sync/noinst/server/crypto_server_openssl.cpp",

    // CLI Tools
    "realm/sync/tools",
]

let notSyncServerSources: [String] = [
    "realm/alloc.cpp",
    "realm/alloc_slab.cpp",
    "realm/array.cpp",
    "realm/array_with_find.cpp",
    "realm/array_backlink.cpp",
    "realm/array_binary.cpp",
    "realm/array_blob.cpp",
    "realm/array_blobs_big.cpp",
    "realm/array_blobs_small.cpp",
    "realm/array_decimal128.cpp",
    "realm/array_fixed_bytes.cpp",
    "realm/array_integer.cpp",
    "realm/array_key.cpp",
    "realm/array_mixed.cpp",
    "realm/array_string.cpp",
    "realm/array_string_short.cpp",
    "realm/array_timestamp.cpp",
    "realm/array_unsigned.cpp",
    "realm/backup_restore.cpp",
    "realm/bplustree.cpp",
    "realm/chunked_binary.cpp",
    "realm/cluster.cpp",
    "realm/cluster_tree.cpp",
    "realm/collection.cpp",
    "realm/column_binary.cpp",
    "realm/db.cpp",
    "realm/decimal128.cpp",
    "realm/dictionary.cpp",
    "realm/disable_sync_to_disk.cpp",
    "realm/error_codes.cpp",
    "realm/exceptions.cpp",
    "realm/global_key.cpp",
    "realm/group.cpp",
    "realm/group_writer.cpp",
    "realm/history.cpp",
    "realm/impl",
    "realm/index_string.cpp",
    "realm/list.cpp",
    "realm/mixed.cpp",
    "realm/node.cpp",
    "realm/obj.cpp",
    "realm/obj_list.cpp",
    "realm/object_id.cpp",
    "realm/query.cpp",
    "realm/query_engine.cpp",
    "realm/query_expression.cpp",
    "realm/query_value.cpp",
    "realm/replication.cpp",
    "realm/set.cpp",
    "realm/sort_descriptor.cpp",
    "realm/spec.cpp",
    "realm/status.cpp",
    "realm/string_data.cpp",
    "realm/sync/changeset.cpp",
    "realm/sync/changeset_encoder.cpp",
    "realm/sync/changeset_parser.cpp",
    "realm/sync/client.cpp",
    "realm/sync/config.cpp",
    "realm/sync/history.cpp",
    "realm/sync/instruction_applier.cpp",
    "realm/sync/instruction_replication.cpp",
    "realm/sync/instructions.cpp",
    "realm/sync/noinst/changeset_index.cpp",
    "realm/sync/noinst/client_history_impl.cpp",
    "realm/sync/noinst/client_impl_base.cpp",
    "realm/sync/noinst/client_reset.cpp",
    "realm/sync/noinst/client_reset_operation.cpp",
    "realm/sync/noinst/compact_changesets.cpp",
    "realm/sync/noinst/compression.cpp",
    "realm/sync/noinst/protocol_codec.cpp",
    "realm/sync/object_id.cpp",
    "realm/sync/protocol.cpp",
    "realm/sync/subscriptions.cpp",
    "realm/sync/transform.cpp",
    "realm/table.cpp",
    "realm/table_cluster_tree.cpp",
    "realm/table_ref.cpp",
    "realm/table_view.cpp",
    "realm/unicode.cpp",
    "realm/util",
    "realm/utilities.cpp",
    "realm/uuid.cpp",
    "realm/version.cpp",
] + syncExcludes

let bidExcludes: [String] = [
    "bid128_acos.c",
    "bid128_acosh.c",
    "bid128_asin.c",
    "bid128_asinh.c",
    "bid128_atan.c",
    "bid128_atan2.c",
    "bid128_atanh.c",
    "bid128_cbrt.c",
    "bid128_cos.c",
    "bid128_cosh.c",
    "bid128_erf.c",
    "bid128_erfc.c",
    "bid128_exp.c",
    "bid128_exp10.c",
    "bid128_exp2.c",
    "bid128_expm1.c",
    "bid128_fdimd.c",
    "bid128_fmod.c",
    "bid128_frexp.c",
    "bid128_hypot.c",
    "bid128_ldexp.c",
    "bid128_lgamma.c",
    "bid128_llquantexpd.c",
    "bid128_llrintd.c",
    "bid128_llround.c",
    "bid128_log.c",
    "bid128_log10.c",
    "bid128_log1p.c",
    "bid128_log2.c",
    "bid128_logb.c",
    "bid128_logbd.c",
    "bid128_lrintd.c",
    "bid128_lround.c",
    "bid128_minmax.c",
    "bid128_modf.c",
    "bid128_nearbyintd.c",
    "bid128_next.c",
    "bid128_nexttowardd.c",
    "bid128_noncomp.c",
    "bid128_pow.c",
    "bid128_quantexpd.c",
    "bid128_quantize.c",
    "bid128_quantumd.c",
    "bid128_rem.c",
    "bid128_round_integral.c",
    "bid128_scalb.c",
    "bid128_scalbl.c",
    "bid128_sin.c",
    "bid128_sinh.c",
    "bid128_sqrt.c",
    "bid128_tan.c",
    "bid128_tanh.c",
    "bid128_tgamma.c",
    "bid128_to_int16.c",
    "bid128_to_int32.c",
    "bid128_to_int8.c",
    "bid128_to_uint16.c",
    "bid128_to_uint32.c",
    "bid128_to_uint64.c",
    "bid128_to_uint8.c",
    "bid32_acos.c",
    "bid32_acosh.c",
    "bid32_add.c",
    "bid32_asin.c",
    "bid32_asinh.c",
    "bid32_atan.c",
    "bid32_atan2.c",
    "bid32_atanh.c",
    "bid32_cbrt.c",
    "bid32_compare.c",
    "bid32_cos.c",
    "bid32_cosh.c",
    "bid32_div.c",
    "bid32_erf.c",
    "bid32_erfc.c",
    "bid32_exp.c",
    "bid32_exp10.c",
    "bid32_exp2.c",
    "bid32_expm1.c",
    "bid32_fdimd.c",
    "bid32_fma.c",
    "bid32_fmod.c",
    "bid32_frexp.c",
    "bid32_hypot.c",
    "bid32_ldexp.c",
    "bid32_lgamma.c",
    "bid32_llquantexpd.c",
    "bid32_llrintd.c",
    "bid32_llround.c",
    "bid32_log.c",
    "bid32_log10.c",
    "bid32_log1p.c",
    "bid32_log2.c",
    "bid32_logb.c",
    "bid32_logbd.c",
    "bid32_lrintd.c",
    "bid32_lround.c",
    "bid32_minmax.c",
    "bid32_modf.c",
    "bid32_mul.c",
    "bid32_nearbyintd.c",
    "bid32_next.c",
    "bid32_nexttowardd.c",
    "bid32_noncomp.c",
    "bid32_pow.c",
    "bid32_quantexpd.c",
    "bid32_quantize.c",
    "bid32_quantumd.c",
    "bid32_rem.c",
    "bid32_round_integral.c",
    "bid32_scalb.c",
    "bid32_scalbl.c",
    "bid32_sin.c",
    "bid32_sinh.c",
    "bid32_sqrt.c",
    "bid32_string.c",
    "bid32_sub.c",
    "bid32_tan.c",
    "bid32_tanh.c",
    "bid32_tgamma.c",
    "bid32_to_bid128.c",
    "bid32_to_bid64.c",
    "bid32_to_int16.c",
    "bid32_to_int32.c",
    "bid32_to_int64.c",
    "bid32_to_int8.c",
    "bid32_to_uint16.c",
    "bid32_to_uint32.c",
    "bid32_to_uint64.c",
    "bid32_to_uint8.c",
    "bid64_acos.c",
    "bid64_acosh.c",
    "bid64_add.c",
    "bid64_asin.c",
    "bid64_asinh.c",
    "bid64_atan.c",
    "bid64_atan2.c",
    "bid64_atanh.c",
    "bid64_cbrt.c",
    "bid64_compare.c",
    "bid64_cos.c",
    "bid64_cosh.c",
    "bid64_div.c",
    "bid64_erf.c",
    "bid64_erfc.c",
    "bid64_exp.c",
    "bid64_exp10.c",
    "bid64_exp2.c",
    "bid64_expm1.c",
    "bid64_fdimd.c",
    "bid64_fma.c",
    "bid64_fmod.c",
    "bid64_frexp.c",
    "bid64_hypot.c",
    "bid64_ldexp.c",
    "bid64_lgamma.c",
    "bid64_llquantexpd.c",
    "bid64_llrintd.c",
    "bid64_llround.c",
    "bid64_log.c",
    "bid64_log10.c",
    "bid64_log1p.c",
    "bid64_log2.c",
    "bid64_logb.c",
    "bid64_logbd.c",
    "bid64_lrintd.c",
    "bid64_lround.c",
    "bid64_minmax.c",
    "bid64_modf.c",
    "bid64_mul.c",
    "bid64_nearbyintd.c",
    "bid64_next.c",
    "bid64_nexttowardd.c",
    "bid64_noncomp.c",
    "bid64_pow.c",
    "bid64_quantexpd.c",
    "bid64_quantize.c",
    "bid64_quantumd.c",
    "bid64_rem.c",
    "bid64_round_integral.c",
    "bid64_scalb.c",
    "bid64_scalbl.c",
    "bid64_sin.c",
    "bid64_sinh.c",
    "bid64_sqrt.c",
    "bid64_string.c",
    "bid64_tan.c",
    "bid64_tanh.c",
    "bid64_tgamma.c",
    "bid64_to_int16.c",
    "bid64_to_int32.c",
    "bid64_to_int64.c",
    "bid64_to_int8.c",
    "bid64_to_uint16.c",
    "bid64_to_uint32.c",
    "bid64_to_uint64.c",
    "bid64_to_uint8.c",
    "bid_binarydecimal.c",
    "bid_dpd.c",
    "bid_feclearexcept.c",
    "bid_fegetexceptflag.c",
    "bid_feraiseexcept.c",
    "bid_fesetexceptflag.c",
    "bid_fetestexcept.c",
    "bid_flag_operations.c",
    "strtod128.c",
    "strtod32.c",
    "strtod64.c",
    "wcstod128.c",
    "wcstod32.c",
    "wcstod64.c",
]

// Xcode 12.0-12.4 will by default attempt to compile hpp files (or warn about
// them not being in sources or excludes) which doesn't work. 12.5 fixes this
// so we can delete this once that's the minimum version we support.
let headers: [String] = [
    "dogless.hpp",
    "realm.hpp",
    "realm/aggregate_ops.hpp",
    "realm/alloc.hpp",
    "realm/alloc_slab.hpp",
    "realm/array.hpp",
    "realm/array_with_find.hpp",
    "realm/array_backlink.hpp",
    "realm/array_basic.hpp",
    "realm/array_basic_tpl.hpp",
    "realm/array_binary.hpp",
    "realm/array_blob.hpp",
    "realm/array_blobs_big.hpp",
    "realm/array_blobs_small.hpp",
    "realm/array_bool.hpp",
    "realm/array_decimal128.hpp",
    "realm/array_direct.hpp",
    "realm/array_fixed_bytes.hpp",
    "realm/array_integer.hpp",
    "realm/array_integer_tpl.hpp",
    "realm/array_key.hpp",
    "realm/array_list.hpp",
    "realm/array_mixed.hpp",
    "realm/array_ref.hpp",
    "realm/array_string.hpp",
    "realm/array_string_short.hpp",
    "realm/array_timestamp.hpp",
    "realm/array_typed_link.hpp",
    "realm/array_unsigned.hpp",
    "realm/backup_restore.hpp",
    "realm/binary_data.hpp",
    "realm/bplustree.hpp",
    "realm/chunked_binary.hpp",
    "realm/cluster.hpp",
    "realm/cluster_tree.hpp",
    "realm/collection.hpp",
    "realm/column_binary.hpp",
    "realm/column_fwd.hpp",
    "realm/column_integer.hpp",
    "realm/column_type.hpp",
    "realm/column_type_traits.hpp",
    "realm/data_type.hpp",
    "realm/db.hpp",
    "realm/db_options.hpp",
    "realm/decimal128.hpp",
    "realm/dictionary.hpp",
    "realm/dictionary_cluster_tree.hpp",
    "realm/disable_sync_to_disk.hpp",
    "realm/error_codes.hpp",
    "realm/exceptions.hpp",
    "realm/exec/importer.hpp",
    "realm/global_key.hpp",
    "realm/group.hpp",
    "realm/group_writer.hpp",
    "realm/handover_defs.hpp",
    "realm/history.hpp",
    "realm/impl/array_writer.hpp",
    "realm/impl/cont_transact_hist.hpp",
    "realm/impl/destroy_guard.hpp",
    "realm/impl/input_stream.hpp",
    "realm/impl/output_stream.hpp",
    "realm/impl/simulated_failure.hpp",
    "realm/impl/transact_log.hpp",
    "realm/index_string.hpp",
    "realm/keys.hpp",
    "realm/list.hpp",
    "realm/metrics/metric_timer.hpp",
    "realm/metrics/metrics.hpp",
    "realm/metrics/query_info.hpp",
    "realm/metrics/transaction_info.hpp",
    "realm/mixed.hpp",
    "realm/node.hpp",
    "realm/node_header.hpp",
    "realm/null.hpp",
    "realm/obj.hpp",
    "realm/obj_list.hpp",
    "realm/object-store/audit.hpp",
    "realm/object-store/binding_callback_thread_observer.hpp",
    "realm/object-store/binding_context.hpp",
    "realm/object-store/c_api/conversion.hpp",
    "realm/object-store/c_api/types.hpp",
    "realm/object-store/c_api/util.hpp",
    "realm/object-store/collection.hpp",
    "realm/object-store/collection_notifications.hpp",
    "realm/object-store/dictionary.hpp",
    "realm/object-store/feature_checks.hpp",
    "realm/object-store/impl/apple/external_commit_helper.hpp",
    "realm/object-store/impl/apple/keychain_helper.hpp",
    "realm/object-store/impl/collection_change_builder.hpp",
    "realm/object-store/impl/collection_notifier.hpp",
    "realm/object-store/impl/deep_change_checker.hpp",
    "realm/object-store/impl/epoll/external_commit_helper.hpp",
    "realm/object-store/impl/external_commit_helper.hpp",
    "realm/object-store/impl/generic/external_commit_helper.hpp",
    "realm/object-store/impl/list_notifier.hpp",
    "realm/object-store/impl/notification_wrapper.hpp",
    "realm/object-store/impl/object_accessor_impl.hpp",
    "realm/object-store/impl/object_notifier.hpp",
    "realm/object-store/impl/realm_coordinator.hpp",
    "realm/object-store/impl/results_notifier.hpp",
    "realm/object-store/impl/transact_log_handler.hpp",
    "realm/object-store/impl/weak_realm_notifier.hpp",
    "realm/object-store/impl/windows/external_commit_helper.hpp",
    "realm/object-store/index_set.hpp",
    "realm/object-store/keypath_helpers.hpp",
    "realm/object-store/list.hpp",
    "realm/object-store/object.hpp",
    "realm/object-store/object_accessor.hpp",
    "realm/object-store/object_changeset.hpp",
    "realm/object-store/object_schema.hpp",
    "realm/object-store/object_store.hpp",
    "realm/object-store/property.hpp",
    "realm/object-store/results.hpp",
    "realm/object-store/schema.hpp",
    "realm/object-store/set.hpp",
    "realm/object-store/shared_realm.hpp",
    "realm/object-store/sync/app.hpp",
    "realm/object-store/sync/app_credentials.hpp",
    "realm/object-store/sync/app_service_client.hpp",
    "realm/object-store/sync/app_utils.hpp",
    "realm/object-store/sync/async_open_task.hpp",
    "realm/object-store/sync/auth_request_client.hpp",
    "realm/object-store/sync/generic_network_transport.hpp",
    "realm/object-store/sync/impl/apple/network_reachability_observer.hpp",
    "realm/object-store/sync/impl/apple/system_configuration.hpp",
    "realm/object-store/sync/impl/network_reachability.hpp",
    "realm/object-store/sync/impl/sync_client.hpp",
    "realm/object-store/sync/impl/sync_file.hpp",
    "realm/object-store/sync/impl/sync_metadata.hpp",
    "realm/object-store/sync/mongo_client.hpp",
    "realm/object-store/sync/mongo_collection.hpp",
    "realm/object-store/sync/mongo_database.hpp",
    "realm/object-store/sync/push_client.hpp",
    "realm/object-store/sync/subscribable.hpp",
    "realm/object-store/sync/sync_manager.hpp",
    "realm/object-store/sync/sync_session.hpp",
    "realm/object-store/sync/sync_user.hpp",
    "realm/object-store/thread_safe_reference.hpp",
    "realm/object-store/util/aligned_union.hpp",
    "realm/object-store/util/android/scheduler.hpp",
    "realm/object-store/util/apple/scheduler.hpp",
    "realm/object-store/util/atomic_shared_ptr.hpp",
    "realm/object-store/util/bson/bson.hpp",
    "realm/object-store/util/bson/indexed_map.hpp",
    "realm/object-store/util/bson/max_key.hpp",
    "realm/object-store/util/bson/min_key.hpp",
    "realm/object-store/util/bson/mongo_timestamp.hpp",
    "realm/object-store/util/bson/regular_expression.hpp",
    "realm/object-store/util/checked_mutex.hpp",
    "realm/object-store/util/copyable_atomic.hpp",
    "realm/object-store/util/event_loop_dispatcher.hpp",
    "realm/object-store/util/generic/scheduler.hpp",
    "realm/object-store/util/scheduler.hpp",
    "realm/object-store/util/tagged_bool.hpp",
    "realm/object-store/util/tagged_string.hpp",
    "realm/object-store/util/uuid.hpp",
    "realm/object-store/util/uv/scheduler.hpp",
    "realm/object_id.hpp",
    "realm/owned_data.hpp",
    "realm/parser/driver.hpp",
    "realm/parser/generated/query_bison.hpp",
    "realm/parser/generated/query_flex.hpp",
    "realm/parser/keypath_mapping.hpp",
    "realm/parser/query_parser.hpp",
    "realm/query.hpp",
    "realm/query_state.hpp",
    "realm/query_conditions.hpp",
    "realm/query_conditions_tpl.hpp",
    "realm/query_engine.hpp",
    "realm/query_expression.hpp",
    "realm/query_value.hpp",
    "realm/replication.hpp",
    "realm/set.hpp",
    "realm/sort_descriptor.hpp",
    "realm/spec.hpp",
    "realm/status.hpp",
    "realm/status_with.hpp",
    "realm/string_data.hpp",
    "realm/sync/changeset.hpp",
    "realm/sync/changeset_encoder.hpp",
    "realm/sync/changeset_parser.hpp",
    "realm/sync/client.hpp",
    "realm/sync/client_base.hpp",
    "realm/sync/config.hpp",
    "realm/sync/history.hpp",
    "realm/sync/impl/clamped_hex_dump.hpp",
    "realm/sync/impl/clock.hpp",
    "realm/sync/instruction_applier.hpp",
    "realm/sync/instruction_replication.hpp",
    "realm/sync/instructions.hpp",
    "realm/sync/noinst/changeset_index.hpp",
    "realm/sync/noinst/client_history_impl.hpp",
    "realm/sync/noinst/client_impl_base.hpp",
    "realm/sync/noinst/client_reset.hpp",
    "realm/sync/noinst/client_reset_operation.hpp",
    "realm/sync/noinst/server/command_line_util.hpp",
    "realm/sync/noinst/compact_changesets.hpp",
    "realm/sync/noinst/compression.hpp",
    "realm/sync/noinst/integer_codec.hpp",
    "realm/sync/noinst/protocol_codec.hpp",
    "realm/sync/noinst/root_certs.hpp",
    "realm/sync/noinst/server/access_control.hpp",
    "realm/sync/noinst/server/access_token.hpp",
    "realm/sync/noinst/server/clock.hpp",
    "realm/sync/noinst/server/crypto_server.hpp",
    "realm/sync/noinst/server/encrypt_fingerprint.hpp",
    "realm/sync/noinst/server/encryption_transformer.hpp",
    "realm/sync/noinst/server/metrics.hpp",
    "realm/sync/noinst/server/permissions.hpp",
    "realm/sync/noinst/server/reopening_file_logger.hpp",
    "realm/sync/noinst/server/server.hpp",
    "realm/sync/noinst/server/server_configuration.hpp",
    "realm/sync/noinst/server/server_dir.hpp",
    "realm/sync/noinst/server/server_file_access_cache.hpp",
    "realm/sync/noinst/server/server_history.hpp",
    "realm/sync/noinst/server/server_impl_base.hpp",
    "realm/sync/noinst/server/server_legacy_migration.hpp",
    "realm/sync/noinst/server/vacuum.hpp",
    "realm/sync/object_id.hpp",
    "realm/sync/protocol.hpp",
    "realm/sync/subscriptions.hpp",
    "realm/sync/transform.hpp",
    "realm/table.hpp",
    "realm/table_cluster_tree.hpp",
    "realm/table_ref.hpp",
    "realm/table_tpl.hpp",
    "realm/table_view.hpp",
    "realm/timestamp.hpp",
    "realm/unicode.hpp",
    "realm/util/aes_cryptor.hpp",
    "realm/util/allocation_metrics.hpp",
    "realm/util/allocator.hpp",
    "realm/util/any.hpp",
    "realm/util/assert.hpp",
    "realm/util/backtrace.hpp",
    "realm/util/base64.hpp",
    "realm/util/basic_system_errors.hpp",
    "realm/util/bind_ptr.hpp",
    "realm/util/buffer.hpp",
    "realm/util/buffer_stream.hpp",
    "realm/util/call_with_tuple.hpp",
    "realm/util/cf_ptr.hpp",
    "realm/util/cf_str.hpp",
    "realm/util/circular_buffer.hpp",
    "realm/util/cli_args.hpp",
    "realm/util/copy_dir_recursive.hpp",
    "realm/util/demangle.hpp",
    "realm/util/duplicating_logger.hpp",
    "realm/util/encrypted_file_mapping.hpp",
    "realm/util/enum.hpp",
    "realm/util/errno.hpp",
    "realm/util/fifo_helper.hpp",
    "realm/util/file.hpp",
    "realm/util/file_is_regular.hpp",
    "realm/util/file_mapper.hpp",
    "realm/util/fixed_size_buffer.hpp",
    "realm/util/flat_map.hpp",
    "realm/util/from_chars.hpp",
    "realm/util/functional.hpp",
    "realm/util/function_ref.hpp",
    "realm/util/future.hpp",
    "realm/util/get_file_size.hpp",
    "realm/util/hex_dump.hpp",
    "realm/util/http.hpp",
    "realm/util/inspect.hpp",
    "realm/util/interprocess_condvar.hpp",
    "realm/util/interprocess_mutex.hpp",
    "realm/util/json_parser.hpp",
    "realm/util/load_file.hpp",
    "realm/util/logger.hpp",
    "realm/util/memory_stream.hpp",
    "realm/util/metered/deque.hpp",
    "realm/util/metered/map.hpp",
    "realm/util/metered/set.hpp",
    "realm/util/metered/string.hpp",
    "realm/util/metered/unordered_map.hpp",
    "realm/util/metered/unordered_set.hpp",
    "realm/util/metered/vector.hpp",
    "realm/util/misc_errors.hpp",
    "realm/util/misc_ext_errors.hpp",
    "realm/util/miscellaneous.hpp",
    "realm/util/network.hpp",
    "realm/util/network_ssl.hpp",
    "realm/util/optional.hpp",
    "realm/util/overload.hpp",
    "realm/util/parent_dir.hpp",
    "realm/util/platform_info.hpp",
    "realm/util/priority_queue.hpp",
    "realm/util/quote.hpp",
    "realm/util/random.hpp",
    "realm/util/resource_limits.hpp",
    "realm/util/safe_int_ops.hpp",
    "realm/util/scope_exit.hpp",
    "realm/util/scratch_allocator.hpp",
    "realm/util/serializer.hpp",
    "realm/util/sha_crypto.hpp",
    "realm/util/signal_blocker.hpp",
    "realm/util/string_buffer.hpp",
    "realm/util/substitute.hpp",
    "realm/util/terminate.hpp",
    "realm/util/thread.hpp",
    "realm/util/thread_exec_guard.hpp",
    "realm/util/time.hpp",
    "realm/util/timestamp_formatter.hpp",
    "realm/util/timestamp_logger.hpp",
    "realm/util/to_string.hpp",
    "realm/util/type_list.hpp",
    "realm/util/type_traits.hpp",
    "realm/util/uri.hpp",
    "realm/util/utf8.hpp",
    "realm/util/value_reset_guard.hpp",
    "realm/util/websocket.hpp",
    "realm/util/ez_websocket.hpp",
    "realm/utilities.hpp",
    "realm/uuid.hpp",
    "realm/version.hpp",
    "realm/version_id.hpp",
]

let package = Package(
    name: "RealmDatabase",
    platforms: [
        .macOS(.v10_10),
        .iOS(.v11),
        .tvOS(.v9),
        .watchOS(.v2)
    ],
    products: [
        .library(
            name: "RealmCore",
            targets: ["RealmCore"]),
        .library(
            name: "RealmQueryParser",
            targets: ["RealmQueryParser"]),
        .library(
            name: "RealmCapi",
            targets: ["Capi"]),
        .library(
            name: "RealmFFI",
            targets: ["RealmFFI"]),
    ],
    targets: [
        .target(
            name: "Bid",
            path: "src/external/IntelRDFPMathLib20U2/LIBRARY/src",
            exclude: bidExcludes,
            publicHeadersPath: "."
        ),
        .target(
            name: "RealmCore",
            dependencies: ["Bid"],
            path: "src",
            exclude: ([
                "CMakeLists.txt",
                "dogless",
                "external",
                "realm/CMakeLists.txt",
                "realm/exec",
                "realm/metrics",
                "realm/object-store/CMakeLists.txt",
                "realm/object-store/c_api",
                "realm/object-store/impl/epoll",
                "realm/object-store/impl/generic",
                "realm/object-store/impl/windows",
                "realm/parser",
                "realm/sync/CMakeLists.txt",
                "realm/tools",
                "realm/util/config.h.in",
                "realm/version_numbers.hpp.in",
                "swift",
                "win32",
            ] + syncExcludes + syncServerSources + headers) as [String],
            publicHeadersPath: ".",
            cxxSettings: cxxSettings,
            linkerSettings: [
                .linkedLibrary("z"),
                .linkedFramework("Security", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .macCatalyst])),
            ]),
        .target(
            name: "RealmQueryParser",
            dependencies: ["RealmCore"],
            path: "src/realm/parser",
            exclude: [
                "CMakeLists.txt",
                "driver.hpp",
                "generated/query_bison.hpp",
                "generated/query_flex.hpp",
                "keypath_mapping.hpp",
                "query_bison.yy",
                "query_flex.ll",
                "query_parser.hpp",
            ],
            publicHeadersPath: ".",
            cxxSettings: [
                .headerSearchPath("realm/parser/generated")
            ] + cxxSettings),
        .target(
            name: "SyncServer",
            dependencies: ["RealmCore"],
            path: "src",
            exclude: ([
                "CMakeLists.txt",
                "dogless",
                "external",
                "realm/CMakeLists.txt",
                "realm/exec",
                "realm/metrics",
                "realm/object-store",
                "realm/parser",
                "realm/sync/CMakeLists.txt",
                "realm/sync/noinst/server/CMakeLists.txt",
                "realm/tools",
                "realm/util/config.h.in",
                "realm/version_numbers.hpp.in",
                "swift",
                "win32",
            ] + notSyncServerSources + headers) as [String],
            sources: ["realm/sync"],
            publicHeadersPath: "realm/sync/impl", // hack
            cxxSettings: cxxSettings),
        .target(
            name: "Capi",
            dependencies: ["RealmCore", "RealmQueryParser"],
            path: "src/realm/object-store/c_api",
            exclude: [
                "CMakeLists.txt",
                "conversion.hpp",
                "logging.hpp",
                "realm.c",
                "types.hpp",
                "util.hpp",
            ],
            publicHeadersPath: ".",
            cxxSettings: (cxxSettings) as [CXXSetting]),
        .target(
            name: "RealmFFI",
            dependencies: ["Capi"],
            path: "src/swift"),
        .target(
            name: "ObjectStoreTestUtils",
            dependencies: ["RealmCore", "SyncServer"],
            path: "test/object-store/util",
            exclude: [
                "baas_admin_api.hpp",
                "event_loop.hpp",
                "index_helpers.hpp",
                "test_file.hpp",
                "test_utils.hpp",
            ],
            publicHeadersPath: ".",
            cxxSettings: ([
                .headerSearchPath(".."),
                .headerSearchPath("../../../external/catch/single_include"),
            ] + cxxSettings) as [CXXSetting]),
        .target(
            name: "ObjectStoreTests",
            dependencies: ["RealmCore", "RealmQueryParser", "ObjectStoreTestUtils"],
            path: "test/object-store",
            exclude: [
                "CMakeLists.txt",
                "backup.cpp",
                "benchmarks",
                "c_api",
                "collection_fixtures.hpp",
                "mongodb",
                "notifications-fuzzer",
                "query.json",
                "sync-1.x.realm",
                "sync-metadata-v4.realm",
                "sync-metadata-v5.realm",
                "sync/session/session_util.hpp",
                "sync/sync_test_utils.hpp",
                "test_backup-olden-and-golden.realm",
                "util",
            ],
            cxxSettings: ([
                .headerSearchPath("."),
                .headerSearchPath("../../external/catch/single_include"),
            ] + cxxSettings) as [CXXSetting],
            linkerSettings: [
                .linkedFramework("Foundation", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS])),
                .linkedFramework("Security", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS])),
            ]),
        .target(
            name: "CapiTests",
            dependencies: ["Capi", "ObjectStoreTestUtils"],
            path: "test/object-store/c_api",
            cxxSettings: ([
                .headerSearchPath("../"),
                .headerSearchPath("../../../external/catch/single_include")
            ] + cxxSettings) as [CXXSetting],
            linkerSettings: [
                .linkedFramework("Foundation", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS])),
                .linkedFramework("Security", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS])),
            ]),
    ],
    cxxLanguageStandard: .cxx1z
)
