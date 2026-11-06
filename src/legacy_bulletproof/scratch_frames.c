/*
 * Legacy Bulletproof scratch-frame compatibility shim.
 *
 * This file owns the mutable side table used by the imported legacy
 * Bulletproof code to emulate nested scratch frames on top of secp256k1's
 * checkpoint API.
 */

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "third_party/secp256k1-zkp/src/scratch_impl.h"

typedef struct purify_bulletproof_scratch_frames {
    secp256k1_scratch *scratch;
    size_t depth;
    size_t checkpoints[32];
    struct purify_bulletproof_scratch_frames *next;
} purify_bulletproof_scratch_frames;

static atomic_flag purify_bulletproof_scratch_frames_lock = ATOMIC_FLAG_INIT;
static purify_bulletproof_scratch_frames *purify_bulletproof_scratch_frames_head = NULL;

static void purify_bulletproof_scratch_frames_acquire_lock(void) {
    while (atomic_flag_test_and_set_explicit(&purify_bulletproof_scratch_frames_lock, memory_order_acquire)) {
    }
}

static void purify_bulletproof_scratch_frames_release_lock(void) {
    atomic_flag_clear_explicit(&purify_bulletproof_scratch_frames_lock, memory_order_release);
}

static purify_bulletproof_scratch_frames *purify_bulletproof_scratch_frames_find(
    secp256k1_scratch *scratch,
    purify_bulletproof_scratch_frames **prev_out
) {
    purify_bulletproof_scratch_frames *prev = NULL;
    purify_bulletproof_scratch_frames *cur = purify_bulletproof_scratch_frames_head;

    while (cur != NULL && cur->scratch != scratch) {
        prev = cur;
        cur = cur->next;
    }
    if (prev_out != NULL) {
        *prev_out = prev;
    }
    return cur;
}

int secp256k1_scratch_allocate_frame(secp256k1_scratch *scratch, size_t n, size_t objects) {
    purify_bulletproof_scratch_frames *frames;
    if (scratch == NULL) {
        return 0;
    }

    purify_bulletproof_scratch_frames_acquire_lock();
    frames = purify_bulletproof_scratch_frames_find(scratch, NULL);
    if (frames == NULL) {
        frames = (purify_bulletproof_scratch_frames *)malloc(sizeof(*frames));
        if (frames == NULL) {
            purify_bulletproof_scratch_frames_release_lock();
            return 0;
        }
        memset(frames, 0, sizeof(*frames));
        frames->scratch = scratch;
        frames->next = purify_bulletproof_scratch_frames_head;
        purify_bulletproof_scratch_frames_head = frames;
    }
    if (frames->depth >= sizeof(frames->checkpoints) / sizeof(frames->checkpoints[0])) {
        purify_bulletproof_scratch_frames_release_lock();
        return 0;
    }
    if (n > secp256k1_scratch_max_allocation(&default_error_callback, scratch, objects)) {
        purify_bulletproof_scratch_frames_release_lock();
        return 0;
    }
    frames->checkpoints[frames->depth++] = secp256k1_scratch_checkpoint(&default_error_callback, scratch);
    purify_bulletproof_scratch_frames_release_lock();
    return 1;
}

void secp256k1_scratch_deallocate_frame(secp256k1_scratch *scratch) {
    purify_bulletproof_scratch_frames *frames;
    purify_bulletproof_scratch_frames *prev;

    VERIFY_CHECK(scratch != NULL);
    purify_bulletproof_scratch_frames_acquire_lock();
    frames = purify_bulletproof_scratch_frames_find(scratch, &prev);
    VERIFY_CHECK(frames != NULL);
    VERIFY_CHECK(frames->depth > 0);
    secp256k1_scratch_apply_checkpoint(&default_error_callback, scratch, frames->checkpoints[--frames->depth]);
    if (frames->depth == 0) {
        if (prev == NULL) {
            purify_bulletproof_scratch_frames_head = frames->next;
        } else {
            prev->next = frames->next;
        }
        free(frames);
    }
    purify_bulletproof_scratch_frames_release_lock();
}
