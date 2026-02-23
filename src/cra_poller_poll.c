#include "cra_poller.h"

#ifdef CRA_WITH_POLL
#include "collections/cra_dict.h"
#include "cra_assert.h"
#include "cra_log.h"
#include "cra_malloc.h"

#ifdef CRA_OS_WIN
#define poll WSAPoll
#endif

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-Poll"

#define Poll ctx

#define CRA_POLLARRAY_INIT_SIZE 64

#define CRA_POLLARRAY_ITEM(_ctx, _index) (((struct pollfd *)(_ctx)->fdarray.array) + (_index))

struct _CraPollerCtx
{
    CraAList fdarray; // AList<struct pollfd>
    CraDict  ios;     // Dict<cra_socket_t, CraIO *>
};

CraPollerCtx *
cra_poller_create_ctx(void)
{
    CraPollerCtx *ctx = cra_alloc(CraPollerCtx);
    if (!ctx)
        return NULL;

    if (!cra_alist_init_size0(struct pollfd, &ctx->fdarray, CRA_POLLARRAY_INIT_SIZE, false))
    {
        CRA_LOG(error, Poll, "Failed to init poll array.");
        cra_dealloc(ctx);
        return NULL;
    }
    if (!cra_dict_init_size0(cra_socket_t,
                             CraIO *,
                             &ctx->ios,
                             CRA_POLLARRAY_INIT_SIZE,
                             false,
                             (cra_hash_fn)cra_hash_socket_p,
                             (cra_compare_fn)cra_compare_socket_p))
    {
        CRA_LOG(error, Poll, "Failed to init poll dict.");
        cra_alist_uninit(&ctx->fdarray);
        cra_dealloc(ctx);
        return NULL;
    }
    CRA_LOG(trace, Poll, "Created.");
    return ctx;
}

void
cra_poller_destroy_ctx(CraPollerCtx *ctx)
{
    if (!ctx)
        return;
    CRA_LOG(trace, Poll, "Destroyed.");
    cra_alist_uninit(&ctx->fdarray);
    cra_dict_uninit(&ctx->ios);
    cra_dealloc(ctx);
}

bool
cra_poller_add(CraPollerCtx *ctx, CraIO *io)
{
    char         *reason;
    size_t        count;
    struct pollfd pfd;

    // 不可重复添加
    assert(io->index == -1);

    pfd.fd = io->fd;
    pfd.events = 0;
    pfd.revents = 0;
    if (io->events & CRA_IO_READ)
        pfd.events |= POLLIN;
    if (io->events & CRA_IO_WRIT)
        pfd.events |= POLLOUT;

    count = cra_alist_get_count(&ctx->fdarray);
    assert(count < INT32_MAX);
    io->index = (int32_t)count;
    if (!cra_alist_append(&ctx->fdarray, &pfd))
    {
        reason = "Failed to add to poll array.";
        goto fail;
    }
    if (!cra_dict_add(&ctx->ios, &pfd.fd, &io))
    {
        cra_alist_remove_back(&ctx->fdarray);
        io->index = -1;
        reason = "Failed to add to poll dict.";
        goto fail;
    }
    CRA_LOG(trace, Poll, "IO event added: fd=%d, events=%d.", (int)io->fd, io->events);
    return true;
fail:
    CRA_LOG(error, Poll, "Failed to add IO event: fd=%d, events=%d. reason: %s.", (int)io->fd, io->events, reason);
    return false;
}

bool
cra_poller_del(CraPollerCtx *ctx, CraIO *io)
{
    int32_t        del;
    int32_t        last;
    size_t         count;
    struct pollfd *pfdptr;
    char          *reason;
    CraIO         *pio;

    assert(io->index >= 0);

#ifndef NDEBUG
    if (!cra_dict_pop(&ctx->ios, &io->fd, NULL, &pio))
    {
        reason = "Failed to remove from poll dict.";
        goto fail;
    }
    assert(pio == io);
#else
    if (!cra_dict_remove(&ctx->ios, &io->fd))
    {
        reason = "Failed to remove from poll dict.";
        goto fail;
    }
#endif

    count = cra_alist_get_count(&ctx->fdarray);
    assert(count > 0 && count < INT32_MAX);
    last = (int32_t)(count - 1);
    del = io->index;
    io->index = -1;

    // 如果要删除的IO不是数组中的最后一个，
    // 则把=最后一个拷贝到被删除的位置
    if (del != last)
    {
        // [(ITEM)(ITEM)...(DEL)...(LAST)] => [(ITEM)(ITEM)...(LAST)...({LAST})]
        cra_alist_get_ptr(&ctx->fdarray, last, (void **)&pfdptr);
        cra_alist_set(&ctx->fdarray, del, pfdptr);
        // (LAST).index = (DEL).index
        cra_dict_get(&ctx->ios, &pfdptr->fd, &pio);
        pio->index = del;
    }
    // 最后删除最后面的IO
    if (cra_alist_remove_at(&ctx->fdarray, last))
    {
        CRA_LOG(trace, Poll, "IO event deleted: fd=%d, events=%d.", (int)io->fd, io->events);
        return true;
    }
    reason = "Failed to remove from poll array.";
fail:
    CRA_LOG(error, Poll, "Failed to delete IO event: fd=%d, events=%d. reason: %s.", (int)io->fd, io->events, reason);
    return false;
}

bool
cra_poller_mod(CraPollerCtx *ctx, CraIO *io)
{
    struct pollfd *pfdptr;
    char          *reason;

    assert(io->index >= 0);

#ifndef NDEBUG
    CraIO *pio;
    if (!cra_dict_get(&ctx->ios, &io->fd, &pio))
    {
        reason = "Failed to find this event in poll dict.";
        goto fail;
    }
    assert(pio == io);
#endif

    if (!cra_alist_get_ptr(&ctx->fdarray, io->index, (void **)&pfdptr))
    {
        reason = "Failed to find this event in poll array.";
        goto fail;
    }

    pfdptr->events = 0;
    if (io->events & CRA_IO_READ)
        pfdptr->events |= POLLIN;
    if (io->events & CRA_IO_WRIT)
        pfdptr->events |= POLLOUT;

    CRA_LOG(trace, Poll, "IO event modified: fd=%d, events=%d.", (int)io->fd, io->events);
    return true;
fail:
    CRA_LOG(error, Poll, "Failed to modify IO event: fd=%d, events=%d. reason: %s.", (int)io->fd, io->events, reason);
    return false;
}

int
cra_poller_poll(CraPollerCtx *ctx, CraAList *active_list, int timeout_ms)
{
    assert(ctx && active_list);

    int            num;
    int            record;
    int32_t        count;
    struct pollfd *pfd;
    CraIO         *io;

    count = (int32_t)ctx->fdarray.count;
    num = poll((struct pollfd *)ctx->fdarray.array, count, timeout_ms);
    if (num > 0)
    {
        record = 0;
        for (int32_t i = 0; i < count; ++i)
        {
            pfd = CRA_POLLARRAY_ITEM(ctx, i);
            if (pfd->fd == CRA_SOCKET_INVALID || pfd->revents == 0)
                continue;

            if (!cra_dict_get(&ctx->ios, &pfd->fd, &io))
                continue;
            assert(io->index >= 0);

            io->revents = CRA_IO_NONE;
            if (pfd->revents & (POLLIN | POLLPRI | POLLHUP | POLLERR | POLLNVAL))
                io->revents |= CRA_IO_READ;
            if (pfd->revents & POLLOUT)
                io->revents |= CRA_IO_WRIT;

            cra_alist_append(active_list, &io);

            if (++record == num)
                break;
        }
        // CRA_LOG(debug, Poll, "Poll completed once with %d active IOs.", num);
    }
    return num;
}

#endif
