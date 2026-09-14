// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * End-to-end enforcement of a DACL that names only native Windows SIDs.
 *
 * Over SMB this is what a descriptor migrated from another server looks like:
 * bare domain SIDs, no POSIX identity anywhere in the ACL, and a mode that
 * grants nothing.  Such a descriptor used to grant nobody, and because a
 * non-empty ACL suppresses the POSIX mode fallback, every non-root caller lost
 * READ_DATA on the file -- it could be stat'ed and not opened.
 *
 * The cases run over memfs through chimera_vfs_read(), so the decision comes
 * from the real VFS access gate rather than from chimera_acl_access_check()
 * called directly (vfs_acl_test.c covers the evaluator itself).  What this adds
 * is the whole chain: the identity layer resolving the caller, the credential
 * SID resolver caching the set, the credential carrying it into the gate, and
 * the backend's stored ACL being matched against it.
 *
 * All setup -- create, chown, ACL set -- runs as a root credential so the
 * scaffolding is never the thing under test; only the read is issued as the
 * caller whose access is being asserted.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#undef NDEBUG
#include <assert.h>

#include "evpl/evpl.h"
#include "vfs/vfs.h"
#include "vfs/vfs_procs.h"
#include "vfs/vfs_release.h"
#include "vfs/vfs_identity.h"
#include "vfs/vfs_cred_sids.h"
#include "vfs/sdk/vfs_attrs.h"
#include "vfs/sdk/vfs_cred.h"
#include "vfs/sdk/vfs_error.h"
#include "vfs/sdk/vfs_acl.h"
#include "vfs/sdk/vfs_sid.h"
#include "common/logging.h"
#include "prometheus-c.h"

#define TEST_PASS(name) fprintf(stderr, "  PASS: %s\n", name)

#define ENF_OWNER_UID 7000
#define ENF_OWNER_GID 7000
#define ENF_USER_UID  7001
#define ENF_USER_GID  7001
#define ENF_GROUP_GID 7002

#define ENF_USER_SID  "S-1-5-21-77-88-99-1101"
#define ENF_GROUP_SID "S-1-5-21-77-88-99-1102"
#define ENF_DEAD_SID  "S-1-5-21-77-88-99-9999"

/* Stack storage for a DACL of `n` ACEs (the one in vfs_acl_test.c is
 * file-local).  Matches that file's shape so the two read alike. */
#define ACL_BUF(name, n)                                              \
        uint8_t name ## _storage[sizeof(struct chimera_acl) +         \
                                 (n) * sizeof(struct chimera_ace)];   \
        struct chimera_acl *name = (struct chimera_acl *) name ## _storage

struct test_ctx {
    int                             done;
    enum chimera_vfs_error          status;
    struct chimera_vfs             *vfs;
    struct chimera_vfs_thread      *vfs_thread;
    struct evpl                    *evpl;
    uint8_t                         fh[CHIMERA_VFS_FH_SIZE];
    uint32_t                        fh_len;
    struct chimera_vfs_open_handle *handle;

    /* Setup identity and the directory everything is created in. */
    struct chimera_vfs_cred         root;
    uint8_t                         root_fh[CHIMERA_VFS_FH_SIZE];
    uint32_t                        root_fh_len;
    struct chimera_vfs_open_handle *root_handle;

    /* The caller under test, and the SID set attached to its credential. */
    struct chimera_vfs_cred         cred;
    struct chimera_vfs_cred_sids    cred_sids;

    /* Where enf_get_acl copies the stored DACL out to. */
    struct chimera_acl             *acl_out;
};

static void
wait_done(struct test_ctx *ctx)
{
    while (!ctx->done) {
        evpl_continue(ctx->evpl);
    }
    ctx->done = 0;
} /* wait_done */

static void
mount_cb(
    struct chimera_vfs_thread *thread,
    enum chimera_vfs_error     status,
    void                      *private_data)
{
    struct test_ctx *ctx = private_data;

    ctx->status = status;
    ctx->done   = 1;
} /* mount_cb */

static void
lookup_cb(
    enum chimera_vfs_error    error_code,
    struct chimera_vfs_attrs *attr,
    void                     *private_data)
{
    struct test_ctx *ctx = private_data;

    ctx->status = error_code;
    if (error_code == CHIMERA_VFS_OK) {
        memcpy(ctx->fh, attr->va_fh, attr->va_fh_len);
        ctx->fh_len = attr->va_fh_len;
    }
    ctx->done = 1;
} /* lookup_cb */

static void
openfh_cb(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *oh,
    void                           *private_data)
{
    struct test_ctx *ctx = private_data;

    ctx->status = error_code;
    ctx->handle = oh;
    ctx->done   = 1;
} /* openfh_cb */

static void
openat_cb(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *oh,
    struct chimera_vfs_attrs       *set_attr,
    struct chimera_vfs_attrs       *attr,
    struct chimera_vfs_attrs       *dir_pre,
    struct chimera_vfs_attrs       *dir_post,
    void                           *private_data)
{
    struct test_ctx *ctx = private_data;

    ctx->status = error_code;
    ctx->handle = oh;
    ctx->done   = 1;
} /* openat_cb */

static void
setattr_cb(
    enum chimera_vfs_error    error_code,
    struct chimera_vfs_attrs *pre_attr,
    struct chimera_vfs_attrs *set_attr,
    struct chimera_vfs_attrs *post_attr,
    void                     *private_data)
{
    struct test_ctx *ctx = private_data;

    ctx->status = error_code;
    ctx->done   = 1;
} /* setattr_cb */

/*
 * Names ENF_USER_UID and ENF_GROUP_GID, and nothing else.  ENF_USER_GID is
 * deliberately unnameable so the caller's primary group contributes no SID:
 * the mixed case must be granted through its supplementary group, not through
 * an accidental primary-group match.
 */
static int
enf_identity_handler(
    enum chimera_vfs_identity_key       key,
    uint32_t                            id,
    const char                         *name,
    struct chimera_vfs_identity_result *out,
    void                               *private_data)
{
    (void) name;
    (void) private_data;

    if (key == CHIMERA_VFS_IDENTITY_BY_UID && id == ENF_USER_UID) {
        out->is_group = 0;
        out->user.uid = ENF_USER_UID;
        out->user.gid = ENF_USER_GID;
        snprintf(out->user.username, sizeof(out->user.username), "enfuser");
        out->user.username_len = (int) strlen(out->user.username);
        snprintf(out->user.sid, sizeof(out->user.sid), ENF_USER_SID);
        return 0;
    }

    if (key == CHIMERA_VFS_IDENTITY_BY_GID && id == ENF_GROUP_GID) {
        out->is_group  = 1;
        out->group.gid = ENF_GROUP_GID;
        snprintf(out->group.groupname, sizeof(out->group.groupname), "enfgrp");
        out->group.groupname_len = (int) strlen(out->group.groupname);
        snprintf(out->group.sid, sizeof(out->group.sid), ENF_GROUP_SID);
        return 0;
    }

    /* Every other id, including ENF_DEAD_SID's, is unresolvable. */
    return -1;
} /* enf_identity_handler */

/* Build a DACL of `n` ALLOW ACEs, each naming a bare SID string. */
static void
enf_build_sid_acl(
    struct chimera_acl *acl,
    const char        **sids,
    unsigned            n,
    uint32_t            mask)
{
    memset(acl, 0, chimera_acl_size(n));
    acl->num_aces = (uint16_t) n;

    for (unsigned i = 0; i < n; i++) {
        acl->aces[i].type        = CHIMERA_ACE_ALLOWED;
        acl->aces[i].access_mask = mask;
        acl->aces[i].who.type    = CHIMERA_PRINCIPAL_SID;
        assert(chimera_sid_from_str(&acl->aces[i].who.sid, sids[i]) == 0);
    }
} /* enf_build_sid_acl */

/* Create `name` in the test directory as root with `set_attr`. */
static void
enf_create(
    struct test_ctx          *ctx,
    const char               *name,
    struct chimera_vfs_attrs *set_attr)
{
    chimera_vfs_open_at(ctx->vfs_thread, &ctx->root, ctx->root_handle, name,
                        strlen(name), CHIMERA_VFS_OPEN_CREATE, set_attr,
                        CHIMERA_VFS_ATTR_FH, 0, 0, openat_cb, ctx);
    wait_done(ctx);
    assert(ctx->status == CHIMERA_VFS_OK);
    assert(ctx->handle != NULL);

    chimera_vfs_release(ctx->vfs_thread, ctx->handle);
    ctx->handle = NULL;
} /* enf_create */

/* Look `name` up as root and open it; leaves the handle in ctx->handle. */
static void
enf_open_root(
    struct test_ctx *ctx,
    const char      *name)
{
    chimera_vfs_lookup(ctx->vfs_thread, &ctx->root, ctx->root_fh,
                       ctx->root_fh_len, name, strlen(name),
                       CHIMERA_VFS_ATTR_FH | CHIMERA_VFS_ATTR_MASK_STAT, 0,
                       lookup_cb, ctx);
    wait_done(ctx);
    assert(ctx->status == CHIMERA_VFS_OK);

    chimera_vfs_open_fh(ctx->vfs_thread, &ctx->root, ctx->fh, ctx->fh_len,
                        CHIMERA_VFS_OPEN_INFERRED, openfh_cb, ctx);
    wait_done(ctx);
    assert(ctx->status == CHIMERA_VFS_OK);
} /* enf_open_root */

/* Apply `set_attr` to `name` as root. */
static void
enf_setattr(
    struct test_ctx          *ctx,
    const char               *name,
    struct chimera_vfs_attrs *set_attr)
{
    enf_open_root(ctx, name);

    chimera_vfs_setattr(ctx->vfs_thread, &ctx->root, ctx->handle, set_attr, 0,
                        0, setattr_cb, ctx);
    wait_done(ctx);
    assert(ctx->status == CHIMERA_VFS_OK);

    chimera_vfs_release(ctx->vfs_thread, ctx->handle);
    ctx->handle = NULL;
} /* enf_setattr */

/*
 * Look `name` up and open it AS THE CALLER UNDER TEST.  The lookup itself runs
 * as root -- directory traversal is not what these cases are about -- but the
 * handle the read is issued on must belong to ctx->cred, since the open cache
 * shards handles (and their cached access grant) per credential.
 */
static void
enf_lookup_open(
    struct test_ctx *ctx,
    const char      *name)
{
    chimera_vfs_lookup(ctx->vfs_thread, &ctx->root, ctx->root_fh,
                       ctx->root_fh_len, name, strlen(name),
                       CHIMERA_VFS_ATTR_FH | CHIMERA_VFS_ATTR_MASK_STAT, 0,
                       lookup_cb, ctx);
    wait_done(ctx);
    assert(ctx->status == CHIMERA_VFS_OK);

    chimera_vfs_open_fh(ctx->vfs_thread, &ctx->cred, ctx->fh, ctx->fh_len,
                        CHIMERA_VFS_OPEN_INFERRED, openfh_cb, ctx);
    wait_done(ctx);
    assert(ctx->status == CHIMERA_VFS_OK);
} /* enf_lookup_open */

/*
 * Create `name` owned by ENF_OWNER_UID with mode 0600 -- a mode that grants the
 * test caller nothing, so any access it gets must come from the DACL -- then
 * set `acl` on it.
 *
 * chimera_vfs_setattr is issued with a freshly built attrs struct because a
 * backend rewrites the caller's va_set_mask in place, so an attrs struct must
 * never be reused across two setattr calls.
 */
static void
enf_create_file_with_acl(
    struct test_ctx    *ctx,
    const char         *name,
    struct chimera_acl *acl)
{
    struct chimera_vfs_attrs set_attr;

    memset(&set_attr, 0, sizeof(set_attr));
    set_attr.va_req_mask = CHIMERA_VFS_ATTR_MODE | CHIMERA_VFS_ATTR_UID |
        CHIMERA_VFS_ATTR_GID;
    set_attr.va_set_mask = set_attr.va_req_mask;
    set_attr.va_mode     = S_IFREG | 0600;
    set_attr.va_uid      = ENF_OWNER_UID;
    set_attr.va_gid      = ENF_OWNER_GID;

    enf_create(ctx, name, &set_attr);

    memset(&set_attr, 0, sizeof(set_attr));
    set_attr.va_req_mask = CHIMERA_VFS_ATTR_ACL;
    set_attr.va_set_mask = CHIMERA_VFS_ATTR_ACL;
    set_attr.va_acl      = acl;

    enf_setattr(ctx, name, &set_attr);
} /* enf_create_file_with_acl */

static void
enf_sids_cb(
    const struct chimera_vfs_cred_sids *sids,
    void                               *private_data)
{
    struct test_ctx *ctx = private_data;

    /* Copy: the resolver only lends its entry for this callback, and the
     * credential below outlives it (see the borrow contract in
     * vfs_cred_sids.h). */
    if (sids) {
        ctx->cred_sids = *sids;
        ctx->cred.sids = &ctx->cred_sids;
    } else {
        ctx->cred.sids = NULL;
    }
    ctx->done = 1;
} /* enf_sids_cb */

/* Build ctx->cred for this caller and attach its resolved SID set. */
static void
enf_resolve_cred(
    struct test_ctx *ctx,
    uint32_t         uid,
    uint32_t         gid,
    uint32_t         ngids,
    const uint32_t  *gids)
{
    chimera_vfs_cred_init_unix(&ctx->cred, uid, gid, ngids, gids);

    chimera_vfs_cred_resolve_sids(ctx->vfs_thread, &ctx->cred,
                                  enf_sids_cb, ctx);
    wait_done(ctx);
} /* enf_resolve_cred */

static void
enf_read_cb(
    enum chimera_vfs_error    error_code,
    uint32_t                  count,
    uint32_t                  eof,
    struct evpl_iovec        *iov,
    int                       niov,
    struct chimera_vfs_attrs *attr,
    void                     *private_data)
{
    struct test_ctx *ctx = private_data;

    (void) count;
    (void) eof;
    (void) attr;

    /* The file is empty, so a granted read returns no buffers to release. */
    assert(niov == 0);
    (void) iov;

    ctx->status = error_code;
    ctx->done   = 1;
} /* enf_read_cb */

/*
 * Attempt a one-byte read as ctx->cred.  This goes through chimera_vfs_read,
 * hence the real gate and the real access check -- which is the point of
 * testing here rather than against chimera_acl_access_check directly.
 */
static enum chimera_vfs_error
enf_try_read(
    struct test_ctx *ctx,
    const char      *name)
{
    enf_lookup_open(ctx, name);

    chimera_vfs_read(ctx->vfs_thread, &ctx->cred, ctx->handle, 0, 1, NULL, 0,
                     0, enf_read_cb, ctx);
    wait_done(ctx);

    chimera_vfs_release(ctx->vfs_thread, ctx->handle);
    ctx->handle = NULL;

    return ctx->status;
} /* enf_try_read */

static void
enf_get_acl_cb(
    enum chimera_vfs_error    error_code,
    struct chimera_vfs_attrs *attr,
    void                     *private_data)
{
    struct test_ctx *ctx = private_data;

    ctx->status = error_code;

    /* va_acl points at backend storage valid only inside this callback, so
     * copy it out here rather than saving the pointer. */
    if (error_code == CHIMERA_VFS_OK &&
        (attr->va_set_mask & CHIMERA_VFS_ATTR_ACL) && attr->va_acl) {
        memcpy(ctx->acl_out, attr->va_acl,
               chimera_acl_size(attr->va_acl->num_aces));
    }

    ctx->done = 1;
} /* enf_get_acl_cb */

/* Read the stored DACL back into `out`. */
static void
enf_get_acl(
    struct test_ctx    *ctx,
    const char         *name,
    struct chimera_acl *out)
{
    enf_open_root(ctx, name);

    ctx->acl_out = out;

    chimera_vfs_getattr(ctx->vfs_thread, &ctx->root, ctx->handle,
                        CHIMERA_VFS_ATTR_MASK_STAT | CHIMERA_VFS_ATTR_ACL,
                        enf_get_acl_cb, ctx);
    wait_done(ctx);

    assert(ctx->status == CHIMERA_VFS_OK);

    chimera_vfs_release(ctx->vfs_thread, ctx->handle);
    ctx->handle = NULL;
} /* enf_get_acl */

/*
 * All-opaque DACL: a single ALLOW ACE naming the caller's user SID.  Before
 * this work it granted nobody and the non-empty ACL suppressed the mode
 * fallback, so the file could be stat'ed and not opened.
 */
static void
test_all_opaque_dacl_grants(struct test_ctx *ctx)
{
    const char *sids[1] = { ENF_USER_SID };
    ACL_BUF(acl, 1);

    enf_build_sid_acl(acl, sids, 1,
                      CHIMERA_ACE_READ_DATA | CHIMERA_ACE_READ_ATTRIBUTES);

    enf_create_file_with_acl(ctx, "opaque_grant", acl);
    enf_resolve_cred(ctx, ENF_USER_UID, ENF_USER_GID, 0, NULL);

    assert(enf_try_read(ctx, "opaque_grant") == CHIMERA_VFS_OK);

    TEST_PASS("an all-SID DACL grants the caller whose SID it names");
} /* test_all_opaque_dacl_grants */

/*
 * A SID nothing can resolve still matches nobody -- the fail-closed default
 * the ticket keeps deliberately.
 */
static void
test_unresolvable_sid_denies(struct test_ctx *ctx)
{
    const char *sids[1] = { ENF_DEAD_SID };
    ACL_BUF(acl, 1);

    enf_build_sid_acl(acl, sids, 1,
                      CHIMERA_ACE_READ_DATA | CHIMERA_ACE_READ_ATTRIBUTES);

    enf_create_file_with_acl(ctx, "opaque_deny", acl);
    enf_resolve_cred(ctx, ENF_USER_UID, ENF_USER_GID, 0, NULL);

    assert(enf_try_read(ctx, "opaque_deny") == CHIMERA_VFS_EACCES);

    TEST_PASS("an unresolvable SID matches no caller");
} /* test_unresolvable_sid_denies */

/*
 * Mixed: one dead SID, one live group SID.  The dead ACE must not poison the
 * walk, and the caller must be granted through its group membership.
 */
static void
test_mixed_dacl(struct test_ctx *ctx)
{
    const char *sids[2] = { ENF_DEAD_SID, ENF_GROUP_SID };
    uint32_t    gids[1] = { ENF_GROUP_GID };
    ACL_BUF(acl, 2);

    enf_build_sid_acl(acl, sids, 2,
                      CHIMERA_ACE_READ_DATA | CHIMERA_ACE_READ_ATTRIBUTES);

    enf_create_file_with_acl(ctx, "opaque_mixed", acl);
    enf_resolve_cred(ctx, ENF_USER_UID, ENF_USER_GID, 1, gids);

    assert(enf_try_read(ctx, "opaque_mixed") == CHIMERA_VFS_OK);

    TEST_PASS("a live group SID grants through a DACL that also holds a dead one");
} /* test_mixed_dacl */

/*
 * The stored descriptor must come back byte-identical: evaluation reads the
 * ACL and never writes it.
 */
static void
test_descriptor_unchanged(struct test_ctx *ctx)
{
    const char *sids[1] = { ENF_USER_SID };
    ACL_BUF(acl, 1);
    ACL_BUF(after, 1);

    memset(after_storage, 0, sizeof(after_storage));

    enf_build_sid_acl(acl, sids, 1,
                      CHIMERA_ACE_READ_DATA | CHIMERA_ACE_READ_ATTRIBUTES);

    enf_create_file_with_acl(ctx, "opaque_stable", acl);
    enf_resolve_cred(ctx, ENF_USER_UID, ENF_USER_GID, 0, NULL);

    assert(enf_try_read(ctx, "opaque_stable") == CHIMERA_VFS_OK);

    enf_get_acl(ctx, "opaque_stable", after);
    assert(memcmp(acl, after, chimera_acl_size(1)) == 0);

    TEST_PASS("the stored descriptor is byte-identical after an access check");
} /* test_descriptor_unchanged */

int
main(
    int    argc,
    char **argv)
{
    struct test_ctx               ctx = { 0 };
    struct chimera_vfs_module_cfg module_cfgs[2];
    struct prometheus_metrics    *metrics;

    (void) argc;
    (void) argv;

    chimera_log_init();

    /* Setup identity: uid 0 is granted everything by the engine regardless of
     * the process the test runs as, so the scaffolding never depends on being
     * root on the host. */
    chimera_vfs_cred_init_unix(&ctx.root, 0, 0, 0, NULL);

    metrics = prometheus_metrics_create(NULL, NULL, 0);
    assert(metrics != NULL);

    memset(module_cfgs, 0, sizeof(module_cfgs));
    snprintf(module_cfgs[0].module_name, sizeof(module_cfgs[0].module_name),
             "memfs");
    snprintf(module_cfgs[1].module_name, sizeof(module_cfgs[1].module_name),
             "memkv");

    ctx.evpl = evpl_create(NULL);
    assert(ctx.evpl != NULL);

    ctx.vfs = chimera_vfs_init(0, 0, module_cfgs, 2, "memkv", 60, 1, 1, 0,
                               metrics);
    assert(ctx.vfs != NULL);

    ctx.vfs_thread = chimera_vfs_thread_init(ctx.evpl, ctx.vfs);
    assert(ctx.vfs_thread != NULL);

    chimera_vfs_identity_register_handler(ctx.vfs, enf_identity_handler, NULL);

    chimera_vfs_mkfs(ctx.vfs_thread, NULL, "memfs", "fs0", NULL, mount_cb,
                     &ctx);
    wait_done(&ctx);
    assert(ctx.status == CHIMERA_VFS_OK);

    chimera_vfs_mount(ctx.vfs_thread, NULL, "/test", "memfs", "fs0", NULL,
                      mount_cb, &ctx);
    wait_done(&ctx);
    assert(ctx.status == CHIMERA_VFS_OK);

    chimera_vfs_get_root_fh(ctx.root_fh, &ctx.root_fh_len);

    chimera_vfs_lookup(ctx.vfs_thread, &ctx.root, ctx.root_fh, ctx.root_fh_len,
                       "test", 4,
                       CHIMERA_VFS_ATTR_FH | CHIMERA_VFS_ATTR_MASK_STAT, 0,
                       lookup_cb, &ctx);
    wait_done(&ctx);
    assert(ctx.status == CHIMERA_VFS_OK);
    memcpy(ctx.root_fh, ctx.fh, ctx.fh_len);
    ctx.root_fh_len = ctx.fh_len;

    chimera_vfs_open_fh(ctx.vfs_thread, &ctx.root, ctx.root_fh,
                        ctx.root_fh_len, CHIMERA_VFS_OPEN_INFERRED, openfh_cb,
                        &ctx);
    wait_done(&ctx);
    assert(ctx.status == CHIMERA_VFS_OK);
    ctx.root_handle = ctx.handle;
    ctx.handle      = NULL;

    test_all_opaque_dacl_grants(&ctx);
    test_unresolvable_sid_denies(&ctx);
    test_mixed_dacl(&ctx);
    test_descriptor_unchanged(&ctx);

    chimera_vfs_release(ctx.vfs_thread, ctx.root_handle);
    ctx.root_handle = NULL;

    chimera_vfs_umount(ctx.vfs_thread, NULL, "/test", mount_cb, &ctx);
    wait_done(&ctx);
    assert(ctx.status == CHIMERA_VFS_OK);

    chimera_vfs_rmfs(ctx.vfs_thread, NULL, "memfs", "fs0", mount_cb, &ctx);
    wait_done(&ctx);
    assert(ctx.status == CHIMERA_VFS_OK);

    chimera_vfs_thread_destroy(ctx.vfs_thread);
    chimera_vfs_destroy(ctx.vfs);
    evpl_destroy(ctx.evpl);
    prometheus_metrics_destroy(metrics);

    fprintf(stderr, "All SID-only DACL enforcement tests passed!\n");
    return 0;
} /* main */
